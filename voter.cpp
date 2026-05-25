#define main original_main
#include "core.cpp"
#undef main

int main() {
    Blockchain bc;

    while (true) {
        // ALWAYS REFRESH BEFORE ANY ACTION
        bc.load_blockchain();

        cout << "\n==============================================" << endl;
        cout << "       VOTER TERMINAL" << endl;
        cout << "==============================================" << endl;
        cout << "1. Voter Registration (Create Account)" << endl;
        cout << "2. Voter Login (Vote)" << endl;
        cout << "3. Exit" << endl;
        cout << "Choice: ";

        int choice;
        cin >> choice;

        // REFRESH AGAIN (important)
        bc.load_blockchain();

        if (choice == 1) {
            user_registration(bc);
        }
        else if (choice == 2) {
            user_login(bc);  // untouched
        }
        else if (choice == 3) {
            break;
        }
    }

    return 0;
}