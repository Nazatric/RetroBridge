#include "retrobridge/elf32_image.h"

#include <cstddef>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    if (argc < 2 || argc > 3) {
        std::cerr << "usage: retrobridge_elf_inspect <ELF-file> [guest-package]\n";
        return 64;
    }

    const std::string path = argv[1];
    const std::string package = argc == 3 ? argv[2] : std::string{};
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        std::cerr << "cannot open ELF file: " << path << '\n';
        return 66;
    }
    const std::vector<char> chars((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    std::vector<std::byte> bytes;
    bytes.reserve(chars.size());
    for (const auto character : chars) bytes.push_back(static_cast<std::byte>(static_cast<unsigned char>(character)));

    auto parsed = retrobridge::runtime::Elf32Image::parse(bytes, path, package);
    if (const auto* diagnostic = std::get_if<retrobridge::runtime::ElfDiagnostic>(&parsed)) {
        std::cerr << diagnostic->format() << '\n';
        return 2;
    }

    const auto& image = std::get<retrobridge::runtime::Elf32Image>(parsed);
    std::cout << "ELF32 EM_ARM"
              << " type=" << (image.type() == 3 ? "ET_DYN" : "ET_EXEC")
              << " entry=0x" << std::hex << image.entry_point() << std::dec
              << " PT_LOAD=" << image.load_segment_count()
              << " DT_NEEDED=" << image.needed_libraries().size() << '\n';
    for (const auto& library : image.needed_libraries()) {
        std::cout << "  needs: " << library << '\n';
    }
    return 0;
}
