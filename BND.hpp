#ifndef BND_HPP
#define BND_HPP

#include <string>
#include <vector>

/** Class for reading and manipulating Patapon BND files **/

class BND
{
    public:
    std::string original_name = "";
    std::string data_file = "";

    uint8_t version = 0; ///Version integer found at 0x4
    int empty_blocks = 0; ///Amount of empty 0x10 blocks from 0x24 to first CRC entry
    bool encrypt = false;

    struct File
    {
        int8_t level;
        std::string name;
        std::vector<unsigned char> data;

        ///debug values, mostly used only after loading file
        uint32_t dbg_data_offset;
    };

    std::vector<File> files;

    BND();
    bool load(const std::string& file);
    bool load(const std::string& dict_file, const std::string& ddata_file, bool encrypted);
    uint32_t count_files();
    uint32_t count_entries();
    std::string get_full_name(int id);
    void replace_file(int id, const std::string& path);
    int get_type(int id);
    void list_all_files();
    void list_sorted_via_offset();
    void extract(int id);
    void extract_gzip(int id);
    void extract_all();
    void extract_literally_everything_dont_use_ever(BND bnd_handle);
    void remove_file(int id);
    void add_file(int id, const std::string& path, bool folder=false);
    void save(const std::string& path);
    void save(const std::string& dict, const std::string& data);
};

#endif // BND_HPP
