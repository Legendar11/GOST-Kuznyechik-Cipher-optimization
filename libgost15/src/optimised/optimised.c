#include <libgost15/libgost15.h>
#include <shared/tables.h>
#include <optimised/optimised_tables.h>
#include <string.h>


const size_t WorkspaceOfScheduleRoundKeys = BlockLengthInBytes * 2;


static void applySTransformation(
        unsigned char *block
) {
    for (int byteIndex_ = 0; byteIndex_ < BlockLengthInBytes; ++byteIndex_) {
        block[byteIndex_] = Pi[block[byteIndex_]];
    }
}


static void applyInversedSTransformation(
        unsigned char *block
) {
    for (int byteIndex_ = 0; byteIndex_ < BlockLengthInBytes; ++byteIndex_) {
        block[byteIndex_] = InversedPi[block[byteIndex_]];
    }
}


static void swapBlocks(
        uint64_t *__restrict left,
        uint64_t *__restrict right
) {
    /* Inequality left != right shall hold. */
    left[0] = left[0] ^ right[0];
    left[1] = left[1] ^ right[1];

    right[0] = left[0] ^ right[0];
    right[1] = left[1] ^ right[1];

    left[0] = left[0] ^ right[0];
    left[1] = left[1] ^ right[1];
}


static void applyLSTransformation(	// Преобразование LS
        const unsigned char *input,	// входной блок (размер в 128 бит)
        uint64_t *output			// выходной блок (размер аналогичен)
) {
    uint64_t left_ = 0, right_ = 0; // левая и правая часть входного операнда

    for (int index_ = 0; index_ < 16; ++index_) { // проход по всем строкам матрицы для левой части
												  // получить результат умножения текущего байта на столбец матрицы
        left_ ^= precomputedLSTableLeft[index_][input[index_]].asQWord;
    }

    for (int index_ = 0; index_ < 16; ++index_) { // проход по всем строкам матрицы для правой части
												  // получить результат умножения текущего байта на столбец матрицы
        right_ ^= precomputedLSTableRight[index_][input[index_]].asQWord;  
    }

    output[0] = left_;
    output[1] = right_;
}


static void applyInversedLSTransformation(	// Обратное преобразование LS
        const unsigned char *input,			// входной блок (размер в 128 бит)
        uint64_t *output					// выходной блок (размер аналогичен)
) { // действия аналогичны как для преобразования LS
    uint64_t left_ = 0, right_ = 0;

    for (int index_ = 0; index_ < 16; ++index_) {
        left_ ^= precomputedInversedLSTableLeft[index_][input[index_]].asQWord;
    }

    for (int index_ = 0; index_ < 16; ++index_) {
        right_ ^= precomputedInversedLSTableRight[index_][input[index_]].asQWord;
    }

    output[0] = left_;
    output[1] = right_;
}


static void applyFTransformation(	// усовершенствованное преобразование F
        int constantIndex,			// текущая итерация расширения раундовых ключей
        uint64_t *__restrict left,	// левый подблок (размер 128 бит)
        uint64_t *__restrict right, // правый подблок (размер 128 бит)
        uint64_t *__restrict temp1, // вспомогательная память #1(размер равен размеру подблока)
        uint64_t *__restrict temp2	// вспомогательная память #2(размер равен размеру подблока)
) {
    temp1[0] = left[0] ^ roundConstantsLeft[constantIndex].asQWord; // преобразование X для левого подблока
    temp1[1] = left[1] ^ roundConstantsRight[constantIndex].asQWord;

    applyLSTransformation((unsigned char *) temp1, temp2); // преобразование LS

    right[0] ^= temp2[0]; // преобразование X для правого подблока
    right[1] ^= temp2[1];

    swapBlocks(left, right); // обмен блоков
}


void scheduleEncryptionRoundKeysForGost15(	// выработка раундовых ключей
        void *__restrict roundKeys,			// раундовые ключи
        const void *__restrict key,			// мастер-ключ (размер 256 бит)
        void *__restrict memory				// вспомогательная память
) {
    uint64_t *memory_ = memory;
    uint64_t *roundKeys_ = roundKeys;

    memcpy(&roundKeys_[0], key, BlockLengthInBytes * 2); // первая пара раундовых ключей

    for (int nextKeyIndex_ = 2, constantIndex_ = 0; // остальные раундовые ключи
         nextKeyIndex_ != NumberOfRounds;
         nextKeyIndex_ += 2) {
        memcpy(&roundKeys_[2 * (nextKeyIndex_)],
               &roundKeys_[2 * (nextKeyIndex_ - 2)],
               BlockLengthInBytes * 2);

        for (int feistelRoundIndex_ = 0; // сеть Фейстеля
             feistelRoundIndex_ < NumberOfRoundsInKeySchedule;
             ++feistelRoundIndex_) {
            applyFTransformation(constantIndex_++,
                                 &roundKeys_[2 * (nextKeyIndex_)],
                                 &roundKeys_[2 * (nextKeyIndex_ + 1)],
                                 &memory_[0],
                                 &memory_[2]);
        }
    }
}


void scheduleDecryptionRoundKeysForGost15(
        void *__restrict roundKeys,
        const void *__restrict key,
        void *__restrict memory
) {
    uint64_t *roundKeys_ = roundKeys;
    uint64_t cache_[2] = {0};

    scheduleEncryptionRoundKeysForGost15(roundKeys, key, memory);

    for (int roundKeyIndex_ = 1; roundKeyIndex_ <= 8; ++roundKeyIndex_) {
        memcpy(cache_,
               &roundKeys_[2 * roundKeyIndex_],
               BlockLengthInBytes);
        applySTransformation((unsigned char *) cache_);
        applyInversedLSTransformation((unsigned char *) cache_,
                                      &roundKeys_[2 * roundKeyIndex_]);
    }
}


void encryptBlockWithGost15(				// Основной алгоритм шифрования
        const void *__restrict roundKeys,	// раундовые ключи (размер 10 * 128 бит)
        void *__restrict data				// входной блок (размер 128 бит)
) {
    uint64_t *data_ = data;
    const uint64_t *roundKeys_ = roundKeys;
    uint64_t cache_[2] = {0};
    size_t round_ = 0;

    for (; round_ < NumberOfRounds - 1; ++round_) {
        cache_[0] = data_[0] ^ roundKeys_[2 * round_]; // преобразование X
        cache_[1] = data_[1] ^ roundKeys_[2 * round_ + 1];

        applyLSTransformation((unsigned char *) cache_, data); // Преобразование LS
    }

    data_[0] = data_[0] ^ roundKeys_[2 * round_];
    data_[1] = data_[1] ^ roundKeys_[2 * round_ + 1];
}


void decryptBlockWithGost15(				// Основной алгоритм дешифрования
        const void *__restrict roundKeys,	// раундовые ключи (размер 10 * 128 бит)
        void *__restrict data				// входной блок (размер 128 бит)
) {
    uint64_t *data_ = data;
    const uint64_t *roundKeys_ = roundKeys;
    uint64_t cache_[2] = {0};
    size_t round_ = NumberOfRounds - 1;

    data_[0] ^= roundKeys_[2 * round_]; // последний раунд
    data_[1] ^= roundKeys_[2 * round_ + 1];
    --round_;

    applySTransformation(data); // предпоследний раунд
    applyInversedLSTransformation((unsigned char *) data, cache_);
    applyInversedLSTransformation((unsigned char *) cache_, data);

    cache_[0] = data_[0] ^ roundKeys_[2 * round_];
    cache_[1] = data_[1] ^ roundKeys_[2 * round_ + 1];
    --round_;

    for (; round_ > 0; --round_) { // раунды идут в обратном порядке
        applyInversedLSTransformation((unsigned char *) cache_, data); // обратное преобразование LS

        cache_[0] = data_[0] ^ roundKeys_[2 * round_]; // преобразование X
        cache_[1] = data_[1] ^ roundKeys_[2 * round_ + 1];
    }

    applyInversedSTransformation((unsigned char *) cache_); // первый раунд

    data_[0] = cache_[0] ^ roundKeys_[2 * round_];
    data_[1] = cache_[1] ^ roundKeys_[2 * round_ + 1];
}
