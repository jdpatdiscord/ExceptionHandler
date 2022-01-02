# ExceptionHandler
A x86-32 and x86-64 exception handler project that is able to record in-depth crash logs on end user systems
In some cases, this is able to record a call stack more intact than Visual Studio (albeit not 100% of the time,) so it is useful as a debugging tool as well.

Features:
Complete call stack with addresses + file/module names and lines if available
C++ exception symbols (e.g. std::runtime_error -> gets "class std::runtime_error")
C++ exception messages (e.g. std::runtime_error("This is a test"); -> gets "This is a test")

Some parts of this are incomplete but the project is functional.
