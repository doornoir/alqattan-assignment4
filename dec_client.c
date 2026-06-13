int run_client(int argc, char* argv[], const char* mode, const char* server_name);

int main(int argc, char* argv[]) {
    return run_client(argc, argv, "DEC", "dec_server");
}
