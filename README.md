# ExceptionHandler
Pitch:</br>
A IA-32/AMD64/Aarch64 exception handler project that is able to record in-depth crash logs on end user systems.
In some cases, this is able to record a call stack more intact than Visual Studio (albeit not 100% of the time,) so it is useful as a debugging tool as well.
If you or your users are crashing and your tools aren't working to find it, this is your solution!

Features:</br>
1. Complete call stack with addresses + file/module names and lines if available</br>
2. C++ exception symbols (e.g. std::runtime_error -> gets "class std::runtime_error")</br>
3. C++ exception messages (e.g. std::runtime_error("This is a test"); -> gets "This is a test")</br>
4. Dumps registers (E.g. eax/rax for IA32/AMD64, Xmm/Ymm/Zmm for SSE/AVX/AVX512, x0-x31 for ARM64, q0-q15 for NEON)</br>

How to Use & Usage Requirements:</br>
1. See `tester_demo.cpp` on how to initialize the project</br>
2. Add `dbghelp.lib` to the linker input in the project config</br>
3. Set the C++ Language Standard to C++14 (This is currently required)</br>

The work that needs to be done on this project is in the form of GitHub issues. Please see the issues page on what needs to be done.

Some parts of this are incomplete but the project is functional. Runs on 10,000+ machines!
