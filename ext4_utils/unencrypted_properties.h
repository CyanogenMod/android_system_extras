#include <string>
#include <fstream>

// key names for properties we use
namespace properties {
    extern const char* key;
    extern const char* ref;
    extern const char* type;
    extern const char* password;
}

/**
 * Class to store data on the unencrypted folder of a device.
 * Note that the folder must exist before this class is constructed.
 * All names must be valid single level (no '/') file or directory names
 * Data is organized hierarchically so we can get a child folder
 */
class UnencryptedProperties
{
public:
    // Opens properties folder on named device.
    // If folder does not exist, construction will succeed, but all
    // getters will return default properties and setters will fail.
    UnencryptedProperties(const char* device);

    // Get named object. Return default if object does not exist or error.
    template<typename t> t Get(const char* name, t default_value = t());

    // Set named object. Return true if success, false otherwise
    template<typename t> bool Set(const char* name, t const& value);

    // Get child properties
    UnencryptedProperties GetChild(const char* name);

    // Remove named object
    bool Remove(const char* name);

    // Get path of folder
    std::string const& GetPath() const {return folder_;}
private:
    UnencryptedProperties();
    bool OK() const;
    std::string folder_;
};


template<typename t> t UnencryptedProperties::Get(const char* name,
                                                  t default_value)
{
    if (!OK()) return default_value;
    t value = default_value;
    std::ifstream(folder_ + "/" + name) >> value;
    return value;
}

template<typename t> bool UnencryptedProperties::Set(const char* name,
                                                     t const& value)
{
    if (!OK()) return false;
    std::ofstream o(folder_ + "/" + name);
    o << value;
    return !o.fail();
}

// Specialized getters/setters for strings
template<> std::string UnencryptedProperties::Get(const char* name,
                                      std::string default_value);

template<> bool UnencryptedProperties::Set(const char* name,
                                           std::string const& value);
