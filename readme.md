# Zebra - private server lua unlocker

## 

Basic WoW Lua unlocker for Vanilla, BC, WotLK, Cata, MoP and WoD.
Unlocks all protected lua functions. Does not add any.

This is done by turning conditional jump instructions into simple jumps or just NOP slides past the jump instruction.
Programmed in C#. Requires .NET 4.5, which you probably already have.

It is probably not detected atleast on the earlier clients. Use on your own risk.

Just fire up your WoW client and run the application and you will see something like this:

![Useage](usage.PNG "Image")

That will unlock all WoW instances.
If you want to just unlock certain WoW instance(s) that can be done by invoking the program from the command line:

```batch
./zebra [PID...]
```
```batch
./zebra 4169
```
```batch
./zebra 4169 6941
```

I have verified that most of the functions are working. But not all of them on every version.
This is what I got so far: <br />
[Protection table](https://creativemind1001.github.io/zebra/protection_table.html)

Antivirus scans:<br />
[Metadefender](https://metadefender.opswat.com/results#!/file/bzE5MDkxMVNrdU1jMXdMTHJTMUZ6Y2t2SVVT/regular/overview) <br />
[VirusTotal](https://www.virustotal.com/gui/file/610658d9461e05910988ad0a927b7e0a8d73e30f34c405795063a7c7fd4e8f46/detection) <br />