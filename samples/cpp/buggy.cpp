#include <iostream>
#include <string>

void find_user(Database& db) {
    std::string owner;
    std::cin >> owner;
    db.execute("SELECT * FROM users WHERE owner='" + owner + "'");
}
