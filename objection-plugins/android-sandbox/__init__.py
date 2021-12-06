from sys import stderr
import tempfile
import click
import delegator
from androguard.misc import APK

from objection.utils.plugin import Plugin
from objection.utils.helpers import clean_argument_flags
from objection.state.connection import state_connection
from objection.console.repl import Repl

import os
from os import path
import json
from tempfile import NamedTemporaryFile
import subprocess
from subprocess import Popen, DEVNULL, STDOUT, PIPE
import signal
from configparser import ConfigParser
import atexit

from .database import Database

@atexit.register
def safely_exit_4a():
    AndroidAppAutoAnalysis.singleton.mitm_proxy_stop()

class MitmProxyException(Exception):
    pass

class AndroidAppAutoAnalysis(Plugin):
    """AndroidAppAutoAnalysis is a collection of hooks, sandbox detection bypass techniques and non-frida tools and commands """
    singleton = None

    def __init__(self, ns):
        """
            Creates a new instance of the plugin
            :param ns:
        """

        global namespace
        self.namespace = namespace

        self.hookset_flags = [
            '--base64',
            '--cipher',
            '--clipboard',
            '--dex',
            '--file',
            '--hash',
            '--json',
            '--library',
            '--log',
            '--preferences',
            '--proxy',
            '--serialize',
            '--socket',
            '--sqlite',
            '--strings',
            '--url',
            '--webview'
        ]

        implementation = {
            'meta': 'Android Application Auto Analysis (4A)',
            'commands': {
                'bypass': {
                    'meta': 'bypass anti-vm, anti-frida and ... techniques.',
                    'commands': {
                        'files': {
                            'meta': 'Hide files that is known as emulator files to bypass anti-vms.',
                            'exec': self.bypass_files,
                            'flags': ['--disable'],
                        },
                        'frida': {
                            'meta': 'Bypass anti-frida and anti-xposed using strstr.',
                            'exec': self.bypass_frida,
                            'flags': ['--disable'],
                        },
                        'icon': {
                            'meta': 'Bypass hide-icon technique.',
                            'exec': self.bypass_icon,
                            'flags': ['--disable'],
                        },
                        'process': {
                            'meta': 'Avoid creating new process in app. some anti-* techniques use a new process to check some data.',
                            'exec': self.bypass_process,
                            'flags': ['--disable'],
                        },
                        'sysproperties': {
                            'meta': 'Use some fake system properties to bypass some anti-vm techniques.',
                            'exec': self.bypass_sysproperties,
                            'flags': ['--disable'],
                        },
                    }
                },
                'faker': {
                    'meta': 'Return fake data instead of real system information to app.',
                    'commands': {
                        'build': {
                            'meta': 'Replace build information with fake data.',
                            'exec': self.faker_build,
                            'flags': ['--disable']
                        },
                        'device': {
                            'meta': 'Replace device information with fake data.',
                            'exec': self.faker_device,
                            'flags': ['--disable']
                        },
                        'hasfile': {
                            'meta': 'Hide files that exist / Show files that don`t exist',
                            'exec': self.faker_hasfile,
                            'flags': ['--disable', '--has-not']
                        },
                        'imsi': {
                            'meta': 'Replace subscriber ID (IMSI) with fake one.',
                            'exec': self.faker_imsi,
                            'flags': ['--disable']
                        },
                        'location': {
                            'meta': 'Replace location with fake one.',
                            'exec': self.faker_location,
                            'flags': ['--disable']
                        },
                        'operator': {
                            'meta': 'Replace operator information with fake data.',
                            'exec': self.faker_operator,
                            'flags': ['--disable']
                        },
                        'phone': {
                            'meta': 'Replace phone information with fake data.',
                            'exec': self.faker_phone,
                            'flags': ['--disable']
                        },
                        'sysproperty': {
                            'meta': 'Replace System (java class) properties with fake data.',
                            'exec': self.faker_sysproperty,
                            'flags': ['--disable']
                        },
                        'useragent': {
                            'meta': 'Replace http user-agent header in all requests with fake one.',
                            'exec': self.faker_useragent,
                            'flags': ['--disable']
                        },
                    }
                },
                'hookset': {
                    'meta': 'Collections of useful hooks which helps you monitor functionality of the app.',
                    'exec': self.hookset,
                    'flags': self.hookset_flags + ['--unhook'],
                },

                'info': {
                    'meta': 'Gather information about application using static analysis.',
                    'commands': {
                        'manifest': {
                            'meta': 'Show AndroidManifest.xml',
                            'exec': self.info_manifest,
                        },
                        'permissions': {
                            'meta': 'List permissions required by app.',
                            'exec': self.info_permissions,
                            'flags': ['--details']
                        },
                        'general': {
                            'meta': 'General information about app.',
                            'exec': self.info_general
                        },
                        'activities': {
                            'meta': 'List activities defined in app.',
                            'exec': self.info_activities
                        },
                        'services': {
                            'meta': 'List services defined in app.',
                            'exec': self.info_services
                        },
                        'receivers': {
                            'meta': 'List receivers defined in app.',
                            'exec': self.info_receivers
                        },
                        'dex': {
                            'meta': 'List or get dex files of app.',
                            'exec': self.info_dex,
                            'flags': ['--list', '--get']
                        },
                        'intents': {
                            'meta': 'List intent-filters defined in app.',
                            'exec': self.info_intents,
                            'flags': ['--no-services', '--no-receivers']
                        }
                    }
                },
                # TODO: sandbox using all parts of tool
                # 'sandbox': {
                #     'meta': 'Start analyzing common application functionalities with one command and get the result as a full report',
                #     'flags': ['--no-screenrecord', '--no-mitm'],
                #     'exec': self.sandbox
                # },
                'mitm': {
                    'meta': 'Preparation for listenting to all the network traffic of device',
                    'commands': {
                        'cert': {
                            'meta': '(root) Install/Uninstall self-signed ca certificate, default is Install. use --uninstall otherwise. (not recommended. use ssl-pinning-bypass instead.)',
                            'flags': ['--uninstall'],
                            'exec': self.mitm_cert
                        },
                        'proxy': {
                            'meta': 'step1: start mitmproxy tool - step2: ssl-pinning-bypass - step3: set proxy for app',
                            'flags': ['--stop', '--no-ssl-pinning-bypass', '--no-mitmproxy', '--quite'],
                            'exec': self.mitm_proxy
                        },
                    }
                },
                'database': {
                    'meta': 'Get data collected by 4a.',
                    'commands': {
                        'get': {
                            'meta': 'get a collection of data you want to see.',
                            'exec': self.data_get,
                            'dynamic': self._get_collection_list
                        },
                        'dump': {
                            'meta': 'dump data stored in databasee to stdout or any file.',
                            'exec': self.data_dump,
                            'flags': ['--stdout']
                        },
                        'print': {
                            'meta': 'print data, when collected.',
                            'exec': self.data_print,
                            'flags': ['--off', '--on']
                        }
                    }
                }
            }
        }

        super().__init__(__file__, ns, implementation)
        self.inject()

        # Useful variables
        self.agent_api = state_connection.get_api()
        self.plugin_dir = path.dirname(path.abspath(__file__))

        # Variables' default value
        self._print_off = True
        self._mitm_proxy_started = False
        self._temp_dir = tempfile.TemporaryDirectory()

        # Init config variables
        conf = self._mitm_config = ConfigParser()
        confpath = path.join(self.plugin_dir, 'config/mitm.ini')
        conf.read_file(open(confpath, 'r'))

        conf = self._faker_config = ConfigParser()
        conf.optionxform = str
        confpath = path.join(self.plugin_dir, 'config/faker.ini')
        conf.read_file(open(confpath, 'r'))

        # Init database singleton
        Database()

        AndroidAppAutoAnalysis.singleton = self

    def on_message_handler(self, message, data):
        """
            handle the messages sent from agent using `send` function.
            :message: the message string
            :data: ?
        """

        msg_type = message['type']
        
        if msg_type == 'error':
            self._error(message['description'])
            try:
                self._log(f"{message['stack']}:{message['lineNumber']}:{message['columnNumber']}")
            except KeyError:
                self._log(message)
        elif msg_type == 'send':
            payload = message['payload']

            try:
                decoded = json.loads(payload)

                #
                # store on DB
                #
                plugin = decoded['plugin']
                del decoded['plugin'] # remove plugin part from decoded payload
                Database.singleton.add_to_plugin(plugin, decoded)
                
                if not self._print_off:
                    self._log(str(decoded), truncate=True)
            except json.decoder.JSONDecodeError:
                self._log(payload)

        # with open('file.txt', 'w+') as f:
        #     f.write(message)
        #     f.write('\n\n')

    def sandbox(self, args: list):
        """
            Runs the sandbox.
            :param args:
            :return:
        """

        if '--no-mitm' not in args:
            self._log('android sslpinning disable --quiet')
            android_disable('--quiet')
        
            self._log('plugin android_sandbox mitm cert')
            self.install_cert()

            self._log('plugin android_sandbox mitm proxy start')
            self.start_mitmproxy()
    
    def mitm_cert(self, args: list):
        uninstall = '--uninstall' in args
        script = 'lib/uninstall_cert.sh' if uninstall else 'lib/install_cert.sh'

        cert = self._mitm_pem_path()
        bashscript = path.join(self.plugin_dir, script)
        o = delegator.run(f'bash {bashscript} {cert}')
        if o.err == '':
            if uninstall:
                self._log('mitm cert successfully uninstalled', 'green')
            else:
                self._log('mitm cert successfully installed', 'green')
        else:
            self._error(o.err)
        
    def mitm_proxy_stop(self):
        # 3. kill mitmproxy
        if hasattr(self, '_mitmproxy'):
            os.killpg(os.getpgid(self._mitmproxy.pid), signal.SIGKILL)
            del self._mitmproxy

            proxyconf = self._mitm_config['Proxy']
            dbpath = proxyconf['db_relative_path']
            if path.isfile(dbpath):
                db = Database(dbpath)
                self._log('Getting mimproxy data collected... don`t stop the process!!!')
                for data in db.get_plugin_data('proxy'):
                    Database.singleton.add_to_plugin('proxy', data)
                db.close_db()
                os.remove(dbpath)
            else:
                self._error(f'mitmproxy database file isn`t exist at {dbpath}!')

        # 2. unset proxy of app
        self.api.mitm_unset_proxy()

        # 1. kill job of ssl pinning bypass
        jobs = self.agent_api.jobs_get()
        for job in jobs:
            if job['type'] == 'android-sslpinning-disable':
                id = job['identifier']
                self.agent_api.jobs_kill(id)

    def mitm_proxy(self, args: list):
        clean = clean_argument_flags(args)
        if '--stop' in args:
            if self._mitm_proxy_started:
                self.mitm_proxy_stop()
                self._log('proxy stopped', 'green')
            else:
                self._error('mitm proxy hasn\'t start yet!')
        else:
            if len(clean) != 2:
                self._usage('plugin 4a mitm proxy <ip> <port>')
                self._log('Note: <ip> should be something that is visible by application and <port> should be something that isn`t used by another executable in this computer.')
                return
            ip = clean[0]
            port = int(clean[1])
            quite = '--quite' in args

            # 1. run mitmproxy
            if '--no-mitmproxy' not in args:
                plugin = path.join(self.plugin_dir, 'mitm.py')
                stderr = stdout = DEVNULL if quite else None
                self._mitmproxy = Popen(f'mitmdump -s "{plugin}" -p {port} --listen-host {ip}',
                                        env=os.environ, shell=True, stderr=stderr, stdout=stdout, preexec_fn=os.setsid)
                self._log(f'mitmproxy PID: {self._mitmproxy.pid}')

            # 2. automatically disable android ssl pinning
            if '--no-ssl-pinning-bypass' not in args:
                self.agent_api.android_ssl_pinning_disable(True)

            # 3. force app to use proxy
            self.api.mitm_set_proxy(ip, port)

            self._mitm_proxy_started = True
            self._log('proxy started', 'green')

    def _log_bypass(self, status, disable):
        if disable:
            if status:
                self._log('Bypass disabled successfully.', 'green')
            else:
                self._log('Bypass is not enabled.', 'red')
        else:
            if status:
                self._log('Bypass enabled successfully.', 'green')
            else:
                self._log('Bypass is already enabled.', 'red')

    def bypass_files(self, args: list):
        disable = '--disable' in args
        if disable:
            status = self.api.disable_bypass_files()
        else:
            status = self.api.bypass_files()
        self._log_bypass(status, disable)

    def bypass_frida(self, args: list):
        disable = '--disable' in args
        if disable:
            status = self.api.disable_bypass_frida()
        else:
            status = self.api.bypass_frida()
        self._log_bypass(status, disable)

    def bypass_icon(self, args: list):
        disable = '--disable' in args
        if disable:
            status = self.api.disable_bypass_icon()
        else:
            status = self.api.bypass_icon()
        self._log_bypass(status, disable)
        
    def bypass_process(self, args: list):
        disable = '--disable' in args
        if disable:
            status = self.api.disable_bypass_process()
        else:
            status = self.api.bypass_process()
        self._log_bypass(status, disable)

    def bypass_sysproperties(self, args: list):
        disable = '--disable' in args
        if disable:
            status = self.api.disable_bypass_sysproperties()
        else:
            status = self.api.bypass_sysproperties()
        self._log_bypass(status, disable)

    def hookset(self, args: list):
        unhook = '--unhook' in args
        if unhook:
            args.remove('--unhook')

        error = False
        for i in range(len(args)):
            if args[i] not in self.hookset_flags:
                self._error(f"There is not hook named {args[i]}")
                error = True
            else:
                # remove `--` from flags
                args[i] = args[i].replace('--', '')
        if error:
            return

        for hook in args:
            hookfunc = getattr(self.api, f'hook_{hook}')
            unhookfunc = getattr(self.api, f'unhook_{hook}')

            if unhook:
                ret = unhookfunc()
                if ret:
                    self._log(f'{hook} unhooked successfully.', 'green')
                else:
                    self._log(f'{hook} is not hooked!', 'red')
            else:
                ret = hookfunc()
                if ret:
                    self._log(f'{hook} hooked successfully.', 'green')
                else:
                    self._log(f'{hook} is already hooked!', 'red')

    def _input_faker_config(self, section):
        defaultconf = f'[{section}]\n'
        section = self._faker_config[section]
        for i in section:
            defaultconf += f'{i}: {section[i]}\n'

        editedconf = click.edit(defaultconf)
        conf = ConfigParser()
        conf.optionxform = str
        conf.read_string(editedconf)
        return dict(conf[section])

    def faker_build(self, args: list):
        if '--disable' in args:
            if self.api.nonfake_build():
                self._log('Fake build information disabled successfully.', 'green')
            else:
                self._log('Fake build is already disabled.', 'red')
            return
        
        fake = self._input_faker_config('FakeBuild')
        if self.api.fake_build(fake):
            self._log('Fake build information enabled successfully.', 'green')
        else:
            self._log('Fake build is already enabled. first disable it.', 'red')

    def faker_device(self, args: list):
        if '--disable' in args:
            if self.api.nonfake_device():
                self._log('Fake device information disabled successfully.', 'green')
            else:
                self._log('Fake device is already disabled.', 'red')
            return
        
        clean = clean_argument_flags(args)
        
        if len(clean) == 1:
            device_id = clean[0]
        else:
            device_id = "012343545456445"
            self._usage('plugin 4a faker device <device id>')
            self._log(f'Used {device_id} as device id, by default.')

        if self.api.fake_device(device_id):
            self._log('Fake device information enabled successfully.', 'green')
        else:
            self._log('Fake device is already enabled.', 'red')

    def faker_hasfile(self, args: list):
        clean = clean_argument_flags(args)
        if len(clean) != 1:
            self._usage('plugin 4a faker hasfile [--disable] [--has-not] <file path>')
            return
        filepath = clean[0]

        if '--disable' in args:
            self.api.nonfake_hasfile(filepath)
            self._log('Fake hasfile disabled or was disabled :)', 'green')
            return
        
        has = '--has-not' not in args
        self.api.fake_hasfile(filepath, has)
        self._log(f'Fake hasfile enabled for file {filepath}.', 'green')

    def faker_imsi(self, args: list):
        if '--disable' in args:
            if self.api.nonfake_imsi():
                self._log('Fake IMSI disabled successfully.', 'green')
            else:
                self._log('Fake IMSI is already disabled.', 'red')
            return
        
        clean = clean_argument_flags(args)
        
        if len(clean) == 1:
            imsi = clean[0]
        else:
            imsi = "310260000000111"
            self._usage('plugin 4a faker imsi <IMSI>')
            self._log(f'Used {imsi} as IMSI, by default.')

        if self.api.fake_imsi(imsi):
            self._log('Fake IMSI enabled successfully.', 'green')
        else:
            self._log('Fake IMSI is already enabled.', 'red')

    def faker_location(self, args: list):
        if '--disable' in args:
            if self.api.nonfake_location():
                self._log('Fake location disabled successfully.', 'green')
            else:
                self._log('Fake location is already disabled.', 'red')
            return
        
        clean = clean_argument_flags(args)
        if len(clean) == 2:
            lat = clean[0]
            long = clean[1]
        else:
            lat = 48.8534
            long = 2.3488
            self._usage('plugin 4a faker location <latitude> <longitude>')
            self._log(f'Used ({lat}, {long}) as location, by default.')

        if self.api.fake_location(lat, long):
            self._log('Fake location enabled successfully.', 'green')
        else:
            self._log('Fake location is already enabled.', 'red')

    def faker_operator(self, args: list):
        if '--disable' in args:
            if self.api.nonfake_operator():
                self._log('Fake operator disabled successfully.', 'green')
            else:
                self._log('Fake operator is already disabled.', 'red')
            return
        
        clean = clean_argument_flags(args)
        if len(clean) == 3:
            network = clean[0]
            operator = clean[1]
            iso = clean[2]
        else:
            network = 'Iran'
            operator = 'IR-TCI'
            iso = 'not'
            self._usage('plugin 4a faker operator <network> <operator> <iso>')
            self._log(f'Used {network} as network, {operator} as operator and {iso} as iso, by default.')

        if self.api.fake_operator(lat, long):
            self._log('Fake operator enabled successfully.', 'green')
        else:
            self._log('Fake operator is already enabled.', 'red')

    def faker_phone(self, args: list):
        if '--disable' in args:
            if self.api.nonfake_phone():
                self._log('Fake phone disabled successfully.', 'green')
            else:
                self._log('Fake phone is already disabled.', 'red')
            return
        
        clean = clean_argument_flags(args)
        if len(clean) == 2:
            phone1 = clean[0]
            phone2 = clean[1]
        else:
            phone1 = "060102030405"
            phone2 = None
            self._usage('plugin 4a faker phone <phone1> [<phone2>]')
            self._log(f'Used {phone1} as phone1, by default.')

        if self.api.fake_phone(phone1, phone2):
            self._log('Fake phone enabled successfully.', 'green')
        else:
            self._log('Fake phone is already enabled.', 'red')

    def faker_sysproperty(self, args: list):
        clean = clean_argument_flags(args)
        

        if '--disable' in args:
            if len(clean) != 1:
                self._usage('plugin 4a faker system property --disable <property>')
                return
            prop = clean[0]

            self.api.nonfake_sysproperty(prop)
            self._log('Fake system property disabled or was disabled :)', 'green')
            return
        else:
            if len(clean) != 2:
                self._usage('plugin 4a faker system property <property> <value>')
                return
            prop = clean[0]
            value = clean[1]

            self.api.fake_sysproperty(prop, value)
            self._log(f'Fake system property enabled for file {prop} with value {value}.', 'green')

    def faker_useragent(self, args: list):
        if '--disable' in args:
            if self.api.nonfake_useragent():
                self._log('Fake user-agent disabled successfully.', 'green')
            else:
                self._log('Fake user-agent is already disabled.', 'red')
            return
        
        clean = clean_argument_flags(args)
        if len(clean) == 2:
            agent = clean[0]
        else:
            agent = "Dalvik/2.1.0 (Linux; U; Android 7.1.1; GT-I9505 Build/NMF26V)"
            self._usage('plugin 4a faker useragent <agent>')
            self._log(f'Used `{agent}` as agent, by default')
            return

        if self.api.fake_useragent(agent):
            self._log('Fake user-agent enabled successfully.', 'green')
        else:
            self._log('Fake user-agent is already enabled.', 'red')

    def _get_app_info(self):
        if not hasattr(self, '_app_info'):
            self._app_info = self.api.utils_app_info()
        return self._app_info

    def _get_apk(self):
        if not hasattr(self, '_apk'):
            info = self._get_app_info()
            app_name = info['appName']
            temp_dir = self._temp_dir.name
            local_apk_path = f'{temp_dir}/{app_name}.apk'
            apk_path = info['packageCodePath']
            
            res1 = subprocess.getstatusoutput(f'adb shell cp {apk_path} /sdcard/base.apk')
            res2 = subprocess.getstatusoutput(f'adb pull /sdcard/base.apk {local_apk_path}')
            if res1[0] != 0 or res2[0] != 0:
                raise Exception('Failed to get APK file!')

            self._apk = APK(local_apk_path)

        return self._apk

    def info_manifest(self, args: list):
        apk = self._get_apk()

        xml = apk.get_android_manifest_axml()
        xml = xml.get_xml().decode()

        click.echo_via_pager(xml)

    def info_permissions(self, args: list):
        apk = self._get_apk()

        if '--details' in args:
            perms = apk.get_details_permissions()
            for k in perms:
                detail = "\n\t".join(perms[k])
                self._log(f'{k}\n\t{detail}')
        else:
            perms = apk.get_permissions()
            self._log('\t' + '\n\t'.join(perms))

    def info_general(self, args: list):
        info = self._get_app_info()
        toprint = '\t'
        for k in info:
            toprint += f'{k}: {info[k]}\n\t'
        self._log(toprint)

    def info_activities(self, args: list):
        apk = self._get_apk()

        acts = apk.get_activities()
        self._log('\t' + '\n\t'.join(acts))

    def info_services(self, args: list):
        apk = self._get_apk()

        servs = apk.get_services()
        self._log('\t' + '\n\t'.join(servs))

    def info_receivers(self, args: list):
        apk = self._get_apk()

        recs = apk.get_receivers()
        self._log('\t' + '\n\t'.join(recs))

    def info_dex(self, args: list):
        if len(args) == 0:
            self._usage('Use flags')
            return

        apk = self._get_apk()
        clean = clean_argument_flags(args)

        dex_names = apk.get_dex_names()
        if '--list' in args:
            self._log('\t' + '\n\t'.join(dex_names))
        elif '--get' in args:
            if len(clean) != 1:
                self._usage('plugin 4a info dex --get <dir path to write files>')
                return
            
            dirpath = clean[0]
            if not path.isdir(dirpath):
                self._error('<dir path to write files> should be a directory.')
                return

            dexes = apk.get_all_dex()
            for name, dex in zip(dex_names, dexes):
                p = path.join(dirpath, name)
                with open(p, 'w+b') as f:
                    f.write(dex)

    def info_intents(self, args: list):
        def intent_str(itemtype, name):
            toprint = '\t' + name + ':\n'
            for action, intent_name in apk.get_intent_filters(itemtype, name).items():
                toprint += '\t\t' + action + ':\n'
                for intent in intent_name:
                    toprint += '\t\t\t' + intent + '\n'
            return toprint

        apk = self._get_apk()

        if '--no-services' not in args:
            toprint = 'Services and their intent-filters:\n'
            services = apk.get_services()
            for service in services:
                toprint += intent_str('service', service)
            self._log(toprint)

        if '--no-receivers' not in args:
            toprint = 'Receivers and their intent-filters:\n'
            receivers = apk.get_receivers()
            for receiver in receivers:
                toprint += intent_str('receiver', receiver)
            self._log(toprint)

    def _get_collection_list(self):
        plugins = Database.singleton.get_plugins()
        return dict(zip(plugins, plugins))
        
    def data_get(self, args: list):
        args = clean_argument_flags(args)
        if len(args) != 1:
            self._usage('plugin 4a database get <collection name>')
            return

        plugin = args[0]
        data = Database.singleton.get_plugin_data(plugin)

        msg = ''
        for i in data:
            msg += str(i) + '\n'

        # click.echo_via_pager(msg)

        # import code
        # code.interact(local=locals())

        self._json(list(data))

    def data_dump(self, args: list):
        # flags
        stdout = '--stdout' in args

        # positional args
        args = clean_argument_flags(args)
        destfile = args[0] if len(args) >= 1 else None

        # usage
        if not stdout and destfile is None:
            self._usage('plugin 4a dump <local destination>')
            return

        # dump data
        plugins = Database.singleton.get_plugins()
        if stdout:
            msg = ''
            
            for plugin in plugins:
                data = Database.singleton.get_plugin_data(plugin)

                header = '=' * 10 + plugin + '=' * 10
                header = '=' * len(header) + '\n' + header + '\n' + '=' * len(header) + '\n'

                msg += header
                for i in data:
                    msg += str(i) + '\n'
            
            click.echo_via_pager(msg)

        else:
            with open(destfile, 'w+') as f:
                for plugin in plugins:
                    data = Database.singleton.get_plugin_data(plugin)
                    for i in data:
                        f.write(str(i) + '\n')

    def data_print(self, args: list):
        self._print_off = '--off' in args

    def _install_fx(self):
        res = subprocess.getstatusoutput("echo '{}' | fx")
        if res[0] != 0:
            self._error("fx not installed (for print result of json)")
            self._log("Please enter sudo password where it's needed.")
            res = subprocess.getstatusoutput("npm version")
            if res[0] != 0:
                self._error("fx is based on nodejs. you don't have nodejs installed :|")
                res = subprocess.getstatusoutput("sudo apt install nodejs")
                if res[0] != 0:
                    raise Exception("Install `nodejs` and `npm` manually and try again!")
            res = subprocess.getstatusoutput("sudo npm install -g fx")
            if res[0] != 0:
                Exception("Couldn't install fx using `sudo npm install -g fx`")

    def _mitm_pem_path(self):
        cert = path.expanduser('~/.mitmproxy/mitmproxy-ca-cert.pem')
        if not path.isfile(cert):
            self._error(f'mitmproxy cert file doesn\'t exist at {cert}!')
            self._log(f'maybe you need to install mitmproxy using `pip install mitmproxy`')
            raise Exception('mitmproxy cert file not found')
        return cert    

    def _error(self, error: str):
        self._log(error, 'red')
    def _log(self, log: str, color: str = 'reset', truncate: bool = False):
        linesize = os.get_terminal_size().columns
        tolog = f'({self.namespace}) {log}'
        if len(tolog) > linesize and truncate:
            tolog = tolog[:linesize - 4] + ' ...'
        click.secho(tolog, fg=color)
    def _usage(self, usage: str):
        click.secho(f'Usage: {usage}', bold=True)
    def _json(self, data: list):
        # pyfx.Controller().run(pyfx.model.DataSourceType.VARIABLE, data)
        self._install_fx()
        with NamedTemporaryFile('w') as f:
            f.write(json.dumps(data, sort_keys=True))
            os.system(f"fx {f.name}")

namespace = '4a'
plugin = AndroidAppAutoAnalysis