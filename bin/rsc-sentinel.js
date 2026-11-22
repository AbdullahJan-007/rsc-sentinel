#!/usr/bin/env node
import { main } from "../dist/cli.js";

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err) => {
    console.error("rsc-sentinel: unexpected error");
    console.error(err);
    process.exitCode = 2;
  });
