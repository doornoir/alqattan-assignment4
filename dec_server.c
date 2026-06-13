int run_server(int argc, char* argv[], const char* expected_mode, int decrypt);

int main(int argc, char* argv[]) {
    return run_server(argc, argv, "DEC", 1);
}
