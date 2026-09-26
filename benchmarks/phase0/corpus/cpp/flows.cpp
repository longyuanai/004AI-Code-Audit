#include <cstdlib>
#include <iostream>
#include <string>

void alternate_source() {
    const char* command = std::getenv("COMMAND");
    system(command);  // phase0-expect vuln
}

void direct_source() {
    std::string command;
    std::cin >> command;
    system(command.c_str());  // phase0-expect vuln
}

void constant_sink() {
    std::string ignored;
    std::cin >> ignored;
    system("echo safe");  // phase0-expect safe
}
