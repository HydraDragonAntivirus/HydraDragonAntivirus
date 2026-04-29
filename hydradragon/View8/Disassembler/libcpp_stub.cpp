#include <cstdlib>
#include <cstdarg>
namespace std { namespace __Cr {
    void __libcpp_verbose_abort(const char*, ...) { ::abort(); }
}}
