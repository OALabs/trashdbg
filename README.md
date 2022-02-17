![trashdbg2](https://user-images.githubusercontent.com/5906222/152447843-d8c87119-ff0e-4570-b18c-741cee3187fe.png)


# The world's worse debugger

Over the course of multiple [**OALABS Twitch**](https://www.twitch.tv/oalabslive) streams we will build the world's worst debugger! The purpose of the streams is to learn more about the inner workings of debugging under Windows and gain a better general understanding of what our tools are doing when we are debugging malware.

## References

Much of the code in this project is heavily copy-pasted from multiple sources on the Internet. We will try to maintain a list of original sources here, but we may occasionally miss sources while on stream. If we missed something let us know so we can add it!
- [Maltracer (@buffer)](https://github.com/buffer/maltracer/blob/master/maltracer.py)
- [Grey Hay Python excercise (@Newlog)](https://github.com/newlog/exploiting/tree/e47984001616cf45fba537698ac1e87a3afbc8ae/training/windows/gray_hat_python/1/custom_debugger)
- [Winappdbg (@MarioVilas)](https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/win32/defines.py)
- [Fastir Collector (@SekoiaLab)](https://github.com/SekoiaLab/Fastir_Collector/blob/master/memory/mem.py)
- [StackOverflow "tasklist does not list all Modules in 64-systems"](https://stackoverflow.com/questions/17474574/tasklist-does-not-list-all-modules-in-64-systems/17477833#17477833)
- [StackOverflow "How to enum modules in a 64bit process from a 32bit WOW process"](https://stackoverflow.com/questions/3801517/how-to-enum-modules-in-a-64bit-process-from-a-32bit-wow-process)
- [EnigmaHWID - hardware breakpoint (@mrexodia)](https://bitbucket.org/mrexodia/enigmahwid/src/master/hwbp.cpp)

## Notes
### System Breakpoint
The "system breakpoint" is set automaticall for a debugged process by `ntdll:LdrpDoDebuggerBreak`. We can receive this in our debugger as a software breakpoint event but we need to be careful... the context debug registers are restored in ntdll after this bp so we cannot set a hardware breakpoint from here it will be cleared!

![oS2S6R9](https://user-images.githubusercontent.com/5906222/153781429-b65d476d-9385-4191-abf9-7b0d6465f8ec.png)

### Hardware Breakpoints
The hardware breakpoint dr registers are set in thread specific context so it is possible to set different hw bp per thread. In practice this is not usually what we want as an analyst -- we want to set a hw bp that fires for all threads. To accomplish this we needed to add some helper methods that track all of the process threads. When a new hw bp is added it is added to all threads, and when a new thread is created the hw bps are added to it.


## No PRs
Because this project is meant to be a community effort on stream we won’t be accepting PRs. Aside from some maintenance/cleanup **all coding will be done on-stream**. If you have feature requests or suggestions leave your feedback as an Issue or come chat with us on [**Discord**](https://discord.gg/UWdMC3W2qn).

## Join Us!
 💖 Check out our [**schedule**](https://www.twitch.tv/oalabslive/schedule) we stream Thursdays and Sundays at 1300 EST

[![Chat](https://img.shields.io/badge/Chat-Discord-blueviolet)](https://discord.gg/UWdMC3W2qn) [![Support](https://img.shields.io/badge/Support-Patreon-FF424D)](https://www.patreon.com/oalabs)
