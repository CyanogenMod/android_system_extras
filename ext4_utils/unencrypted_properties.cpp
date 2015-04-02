#include "unencrypted_properties.h"

#include <sys/stat.h>

namespace properties {
    const char* key = "key";
    const char* ref = "ref";
    const char* type = "type";
    const char* password = "password";
}

namespace
{
    const char* unencrypted_folder = "unencrypted";
}

UnencryptedProperties::UnencryptedProperties(const char* device)
  : folder_(std::string() + device + "/" + unencrypted_folder)
{
}

UnencryptedProperties::UnencryptedProperties()
{
}

template<> std::string UnencryptedProperties::Get(const char* name,
                                      std::string default_value)
{
    if (!OK()) return default_value;
    std::ifstream i(folder_ + "/" + name, std::ios::binary);
    if (!i) {
        return default_value;
    }

    i.seekg(0, std::ios::end);
    int length = i.tellg();
    i.seekg(0, std::ios::beg);
    if (length == -1) {
        return default_value;
    }

    std::string s(length, 0);
    i.read(&s[0], length);
    if (!i) {
        return default_value;
    }

    return s;
}

template<> bool UnencryptedProperties::Set(const char* name, std::string const& value)
{
    if (!OK()) return false;
    std::ofstream o(folder_ + "/" + name, std::ios::binary);
    o << value;
    return !o.fail();
}

UnencryptedProperties UnencryptedProperties::GetChild(const char* name)
{
    UnencryptedProperties e4p;
    if (!OK()) return e4p;

    std::string directory(folder_ + "/" + name);
    if (mkdir(directory.c_str(), 700) == -1 && errno != EEXIST) {
        return e4p;
    }

    e4p.folder_ = directory;
    return e4p;
}

bool UnencryptedProperties::Remove(const char* name)
{
    if (remove((folder_ + "/" + name).c_str())
        && errno != ENOENT) {
        return false;
    }

    return true;
}

bool UnencryptedProperties::OK() const
{
    return !folder_.empty();
}
