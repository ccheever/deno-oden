import lp from "npm:left-pad" with { grants: "fs:read:./data,network:fetch:api.example.com" };
import "npm:runner" with { grants: "run:git" };
import { y } from "./util.js";
console.log(typeof lp, y);
