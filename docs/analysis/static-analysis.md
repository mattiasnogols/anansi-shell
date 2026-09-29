# Static analysis

    .venv/bin/pip install bandit
    .venv/bin/bandit -r .


## Findings

- B602 (high), client.py:156: execute() runs the operator command with
  shell=True. 
- B311 (low), 13 times: reconnect jitter, cipher pick, mutation names and
  junk values. 
- B404, B603 (low): the subprocess import, and the selfcheck subprocess in
  mutate_self().


## Generations

The client rewrites itself after every session, so two scans of "the
client" see different code. Five generations from the client's own
pipeline:

    gen0  ecd2882215cd7eee349c248176a65d4044698a4f445e602bf489b966c3043a0c
    gen1  192eb216461002d1c6e4e995322882dc9953aabebc7b7fd25b50c352844a75f8
    gen2  0190a7b517aeac264dbf4208fc92f0ae5011f9c64754a22e80708b27c6c76bc6
    gen3  d817c98414f92d6b30105763b4eca1577be080f61f6b00bfb3dbce11c1d9c6e7
    gen4  9593ad60b4d6a0ad7c8ca9be63b9a93c1aedb4f46b68ba75364a4a461377ed50

gen0 is client.py as committed. The same bandit run on gen4 reports the same 15 findings. The structure changes between analyses, the findings do not.



## VirusTotal


gen0, gen2 and gen4 (hashes above) were uploaded. A report URL embeds
the file's sha256, so the scanned bytes are these exact files:

- [gen0](https://www.virustotal.com/gui/file/ecd2882215cd7eee349c248176a65d4044698a4f445e602bf489b966c3043a0c): 0 detections
- [gen2](https://www.virustotal.com/gui/file/0190a7b517aeac264dbf4208fc92f0ae5011f9c64754a22e80708b27c6c76bc6): 0 detections
- [gen4](https://www.virustotal.com/gui/file/9593ad60b4d6a0ad7c8ca9be63b9a93c1aedb4f46b68ba75364a4a461377ed50): 0 detections

VirusTotal tries to match signatures of samples
seen in the wild; since this tool was never distributed, 0 detections is the expected result.


Of course, **zero detections does not mean being undetectable**: a YARA rule, host-side dynamic analysis, or a packaged binary would each find it.