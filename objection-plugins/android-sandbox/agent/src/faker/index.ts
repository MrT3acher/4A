import { build } from "./build";
import { device } from "./device";
import { hasfile } from "./hasfile";
import { imsi } from "./imsi";
import { location } from "./location";
import { operator } from "./operator";
import { phone } from "./phone";
import { sysproperty } from "./sysproperty";
import { useragent } from "./useragent";

export const fakes = {
    fakeBuild: build.up,
    fakeDevice: device.up,
    fakeHasfile: hasfile.fake,
    fakeImsi: imsi.up,
    fakeLocation: location.up,
    fakeOperator: operator.up,
    fakePhone: phone.up,
    fakeSysproperty: sysproperty.fake,
    fakeUseragent: useragent.up
}

export const nonfakes = {
    nonfakeBuild: build.down,
    nonfakeDevice: device.down,
    nonfakeHasfile: hasfile.nonfake,
    nonfakeImsi: imsi.down,
    nonfakeLocation: location.down,
    nonfakeOperator: operator.down,
    nonfakePhone: phone.down,
    nonfakeSysproperty: sysproperty.nonfake,
    nonfakeUseragent: useragent.down
}