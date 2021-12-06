import { Switch } from "../lib/switch";

const $System = Java.use('java.lang.System')

var defaultAgent = null

function fake(agent)
{
    var systemInstance = $System.$new();
    defaultAgent = systemInstance.getProperty('http.agent')
    systemInstance.setProperty('http.agent', agent);
}

function nonfake()
{
    var systemInstance = $System.$new();
    systemInstance.setProperty('http.agent', defaultAgent);
}

export const useragent = new Switch(fake, nonfake)