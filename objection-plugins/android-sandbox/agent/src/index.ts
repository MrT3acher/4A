import { bypass, disableBypass } from "./bypass/index";
import { fakes, nonfakes } from "./faker/index";
import { hooks, unhooks } from "./hookset/index"
import * as utils from "./utils"
import * as mitm from "./mitm"

rpc.exports = {
  ...bypass,
  ...disableBypass,

  ...fakes,
  ...nonfakes,

  ...hooks,
  ...unhooks,

  ...mitm,

  ...utils,
};
