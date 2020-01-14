#include <stdio.h>
#include <stdlib.h>
#include <math.h>

/* 鍵を構造体として宣言 */
struct OpenKey { // 公開鍵
    unsigned long long int N;
    unsigned long long int e;
};

struct SecretKey { // 秘密鍵
    unsigned long long int N;
    unsigned long long int d;
};

// RSAの基本的な関数
void generate_key(struct SecretKey *secret_key);
void get_e(unsigned long long int);
unsigned long long int get_d(unsigned long long int L);
unsigned long long int encrypt(unsigned long long int plain_text);
unsigned long long int decrypt(unsigned long long int cryptogram, struct SecretKey secret_key);
unsigned long long int modPow(unsigned long long int b, unsigned long long int e, unsigned long long int m);

// 解読用の関数
unsigned long long int rho_func(unsigned long long int);
unsigned long long int rho_prime_factorize();
void decoding(unsigned long long int c);

// 便利な関数
void print_key();
unsigned long long int gcd(unsigned long long int, unsigned long long int);
int check_prime(unsigned long long int a);

// 公開鍵をグローバルで定義
struct OpenKey open_key;

int main(){
    struct SecretKey secret_key; // 秘密鍵
    int plain_text; // 平文
    unsigned long long int cryptogram; // 暗号文
    int result; // 復号文
    char question;

    // 鍵の作成
    generate_key(&secret_key);

    // 公開鍵の出力
    print_key();

    // 平文の入力
    while(1) {
        puts("2桁の数値を入力してください");
        scanf("%d", &plain_text);
        if(10 <= plain_text && plain_text < 100){
            break;
        }
    }

    // 暗号化
    cryptogram = encrypt(plain_text);

    puts("\n暗号化に成功しました!");
    printf("暗号化した文は%lldです\n", cryptogram);

    while(1) {
        printf("秘密鍵を所持していますか？(y/n): ");
        question = getchar();
        question = getchar();
        if(question == 'y'){
            result = decrypt(cryptogram, secret_key);
            printf("復号した文は%dです\n", result);
            break;
        } else if (question == 'n'){
            puts("\nあなたは暗号文を持っています");
            while(1) {
                printf("公開鍵を使って解読しますか？(y/n): ");
                question = getchar();
                question = getchar();
                if (question == 'y') {
                    decoding(cryptogram);
                    return 0;
                } else if (question == 'n') {
                    return 0;
                }
            }
        }
    }

    return 0;
}


/* -------------------- RSAの基本的な関数 ------------------------- */

// 鍵の生成
void generate_key(struct SecretKey *secret_key) {
    unsigned long long int p, q; // 素数
    unsigned long long int L;
    int err;

    // p, qの入力
    while(1) {
        puts("素数を2つ入力してください ex)2129 2131");
        scanf("%lld %lld", &p, &q);

        // 素数か判定
        err = check_prime(p);
        if(err != 0){
            printf("%lluは素数ではありません\n", p);
            continue;
        }
        err = check_prime(q);
        if(err != 0) {
            printf("%lluは素数ではありません\n", q);
            continue;
        }
        break;
    }

    secret_key->N = open_key.N = p * q;
    L = (p-1) * (q-1);

    get_e(L);
    secret_key->d = get_d(L);
    if(secret_key->d == -1){
        puts("something error!");
        exit(1);
    }
}

// eの入力をチェックする(Lと互いに素であるかどうか)
void get_e(unsigned long long int L) {
    printf("1 < e < %llu かつ %lluと互いに素な数eを入力してください\n", open_key.N, L);
    while(1) {
        scanf("%lld", &open_key.e);
        // 範囲の確認
        if(1 < open_key.e && open_key.e < open_key.N) {
            // 互いに素かの確認
            if (gcd(open_key.e, L) == 1) {
                break;
            } else {
                puts("互いに素な数字を入力してください");
            }
        } else {
            printf("1 < e < %lluの範囲で入力してください\n", open_key.N);
        }
    }
}

// 秘密鍵dを求める
unsigned long long int get_d(unsigned long long int L) {
    unsigned long long int i;

    for(i=1;i<L;i++){
        if((open_key.e * i) % L == 1){
            return i;
        }
    }

    return -1;
}

// 暗号化
unsigned long long int encrypt(unsigned long long int plain_text) {
    return modPow(plain_text, open_key.e, open_key.N);
}

// 復号化
unsigned long long int decrypt(unsigned long long int cryptogram, struct SecretKey secret_key){
    return modPow(cryptogram, secret_key.d, secret_key.N);
}


/* -------------------- 解読用の関数 ------------------------- */

// 暗号解読のmain関数
void decoding(unsigned long long int c){
    unsigned long long int p, q;
    struct SecretKey fake_secret_key;
    int result;

    // Nを素因数分解
    p = rho_prime_factorize();
    q = (unsigned long long int)(open_key.N / p);

    // 秘密鍵の偽造
    fake_secret_key.d = get_d((p-1) * (q-1));
    fake_secret_key.N = open_key.N;

    result = decrypt(c, fake_secret_key);
    printf("解読した平文は%dです\n", result);
}

// ロー法の関数
unsigned long long int rho_func(unsigned long long int a){
    return (a * a + 1) % open_key.N;
}

// ロー法(素因数分解を行う)
// ref https://mathtrain.jp/rhoalgorithm
unsigned long long int rho_prime_factorize(){
    unsigned long long int x, y;
    unsigned long long int prime_num[5] = {2, 3, 5, 7, 11}; // xの初期値の素数
    unsigned long long int i, j, k=0;
    unsigned long long int d;

    for(i=1;;i++){
        // iが1のときは素数を初期値として代入
        x = y = (i == 1) ? prime_num[k] : rho_func(x);
        // y_i = x_2i となるように計算
        for(j=0;j<i;j++){
            y = rho_func(y);
        }
        // |x_i - y_i|とNの最大公約数
        d = gcd((int)fabs((double)x - (double)y), open_key.N);
        if(d==1){
            continue;
        } else if(1 < d && d < open_key.N){
            return d;
        } else if( d == open_key.N){
            i = 0;
            k++;
            if(k >= 5){
                puts("解読失敗");
                exit(1);
            }
        }
    }
}


/* -------------------- 便利な関数 ------------------------- */

// 鍵を出力する関数
void print_key() {
    puts("\n----------- 公開鍵 -----------");
    printf(" e = %lld, N = %lld\n", open_key.e, open_key.N);
    puts("------------------------------\n");
}

// 最大公約数を返す
unsigned long long int gcd(unsigned long long int a, unsigned long long int b) {
    return a % b == 0 ? b : gcd(b, a % b);
}

// 素数を判定
int check_prime(unsigned long long int a){
    unsigned long long int i;
    double sqrtNum;

    if(a < 2) return 1; // 2未満は素数ではない
    else if(a == 2) return 0; // ２は素数
    else if(a % 2 == 0) return 1; // 2以外の偶数は素数ではない

    // 奇数に対して素数の判定を行う
    sqrtNum = sqrt((double)a);
    for(i=3;i<=sqrtNum;i+=2) {
        if(a % i == 0) return 1;
    }

    return 0;
}

// バイナリ法
// ref https://ja.wikipedia.org/wiki/%E5%86%AA%E5%89%B0%E4%BD%99
unsigned long long int modPow(unsigned long long int b, unsigned long long int e, unsigned long long int m) {
    unsigned long long int result = 1;

    while (e > 0) {
        if ((e & 1) == 1) result = (result * b) % m;
        e >>= 1;
        b = (b * b) % m;
    }

    return result;
}
