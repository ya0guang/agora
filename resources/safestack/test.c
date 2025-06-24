int test_args(int arg1, int arg2, int arg3) {
    int r = arg1 + arg2 + arg3;
    return r;
}

int test_array1() {
    int a[100];
    for (int i = 0; i < 100; i++) {
        a[i] = i;
    }
    return a[99];
}

int test_array2(int size) {
    int a[size];
    for (int i = 0; i < size; i++) {
        a[i] = i;
    }
    return a[size - 1];
}

int main(int argc, char const *argv[])
{
    int arg1 = 1;
    int arg2 = 2;
    int arg3 = 3;
    int r = test_args(arg1, arg2, arg3);
    r = test_array1();
    r = test_array2(r);
}
