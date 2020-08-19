#include <iostream>
#include <chrono>
#include <thread>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <random>
#include <algorithm>
#include <libgost15/libgost15.h>
#include <intrin.h>

#pragma intrinsic(__rdtsc)

const auto defaultDuration = std::chrono::duration<double, std::milli>(2000.);

enum units_t {
    kilobitsPerSecond
};

static void generateRandomBytes(uint8_t *bytes, size_t numberOfBytes) {
    std::random_device device_;
    std::mt19937 engine_(device_());
    std::uniform_int_distribution<int> distribution_(0x00, 0xff);
    auto generator_ = std::bind(distribution_, engine_);

    std::generate_n(bytes, numberOfBytes, generator_);
};


static std::string reportPerformance(std::string operation, std::string performance, bool isInProgress = false) {
    std::string result_ = std::string(80, ' ');

    if (!isInProgress) {
        std::copy(operation.begin(), operation.end(), result_.begin() + 3);
        std::copy(performance.begin(), performance.end(), result_.begin() + 55);
        result_[79] = '\n';
    }
    else {
        result_[1] = '.';
        std::copy(operation.begin(), operation.end(), result_.begin() + 3);
        result_[79] = '\r';
    }

    return result_;
}


static std::string toHumanReadable(double performance, enum units_t units) {
    std::ostringstream stream_;

    switch (units) {
        case kilobitsPerSecond: {
            stream_ << std::fixed;
            stream_ << std::setprecision(4);

            if (performance >= 1100.) {
                stream_ << performance / 1000;
                stream_ << " ";
                stream_ << "MB/s";
            }
            else {
                stream_ << performance;
                stream_ << " ";
                stream_ << "kB/s";
            }
        }
            break;
        default:
            break;
    }

    return stream_.str();
}


void benchmarkEncryption(std::chrono::duration<double, std::milli> minimumDuration) {
    std::string operation_ = "Block encryption";
    std::chrono::duration<double, std::milli> duration_(.0);
    double kBPerSecond_ = .0;

    /* Resources allocation. */
    uint8_t *roundKeys_ = new uint8_t[BlockLengthInBytes * NumberOfRounds];
    uint8_t *block_ = new uint8_t[BlockLengthInBytes];

    /* Initialisation. */
    generateRandomBytes(roundKeys_, sizeof roundKeys_);
    generateRandomBytes(block_, sizeof block_);

    /* Measurement-in-progress output. */
    std::cout << reportPerformance(operation_, "", true);

    /* Measurement cycle. */
    for (size_t iterations_ = 1; duration_ < minimumDuration; iterations_ *= 2) {
        auto startedAt_ = std::chrono::high_resolution_clock::now();

        for (size_t iterationIndex_ = 0; iterationIndex_ < iterations_; ++iterationIndex_) {
            encryptBlockWithGost15(roundKeys_, block_);
        }

        auto finishedAt_ = std::chrono::high_resolution_clock::now();
        duration_ = finishedAt_ - startedAt_;
		std::cout << "";

        kBPerSecond_ = (iterations_ * BlockLengthInBytes) / (duration_.count());
    }

    /* Result output. */
    std::cout << reportPerformance(operation_, toHumanReadable(kBPerSecond_, kilobitsPerSecond));

    /* Resources releasing. */
    delete[] roundKeys_;
    delete[] block_;
}

void benchmarkEncryption1() {
	std::string operation_ = "Block encryption";
	const int COUNT_ITERATIONS = 100000;

	/* Resources allocation. */
	uint8_t *roundKeys_ = new uint8_t[BlockLengthInBytes * NumberOfRounds];
	uint8_t *block_ = new uint8_t[BlockLengthInBytes];

	/* Initialisation. */
	generateRandomBytes(roundKeys_, sizeof roundKeys_);
	generateRandomBytes(block_, sizeof block_);

	/* Measurement-in-progress output. */
	std::cout << reportPerformance(operation_, "", true);

	/* Measurement cycle. */
	double result = 0.0;

	
	for (int i = 0; i < COUNT_ITERATIONS; i++)
	{
		generateRandomBytes(roundKeys_, sizeof roundKeys_);
		generateRandomBytes(block_, sizeof block_);

		auto startedAt_ = __rdtsc();
		encryptBlockWithGost15(roundKeys_, block_); 
		auto finishedAt_ = __rdtsc();
		auto duration_ = finishedAt_ - startedAt_;
		result += duration_;
	}

	
	
	std::cout << result / COUNT_ITERATIONS;
		

	/* Result output. */

	/* Resources releasing. */
	delete[] roundKeys_;
	delete[] block_;
}

void benchmarkDecryption(std::chrono::duration<double, std::milli> minimumDuration) {
    std::string operation_ = "Block decryption";
    std::chrono::duration<double, std::milli> duration_(.0);
    double kBPerSecond_ = .0;

    /* Resources allocation. */
    uint8_t *roundKeys_ = new uint8_t[BlockLengthInBytes * NumberOfRounds];
    uint8_t *block_ = new uint8_t[BlockLengthInBytes];

    /* Initialisation. */
    generateRandomBytes(roundKeys_, sizeof roundKeys_);
    generateRandomBytes(block_, sizeof block_);

    /* Measurement-in-progress output. */
    std::cout << reportPerformance(operation_, "", true);

    /* Measurement cycle. */
    for (size_t iterations_ = 1; duration_ < minimumDuration; iterations_ *= 2) {
        auto startedAt_ = std::chrono::high_resolution_clock::now();

        for (size_t iterationIndex_ = 0; iterationIndex_ < iterations_; ++iterationIndex_) {
            decryptBlockWithGost15(roundKeys_, block_);
        }

        auto finishedAt_ = std::chrono::high_resolution_clock::now();
        duration_ = finishedAt_ - startedAt_;
		std::cout << "";

        kBPerSecond_ = (iterations_ * BlockLengthInBytes) / (duration_.count());
    }

    /* Result output. */
    std::cout << reportPerformance(operation_, toHumanReadable(kBPerSecond_, kilobitsPerSecond));

    /* Resources releasing. */
    delete[] roundKeys_;
    delete[] block_;
}

void Enc() {
	const int BLOCK_COUNT = 4096;

	const uint8_t roundKeys_[NumberOfRounds * BlockLengthInBytes] = {
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xdb, 0x31, 0x48, 0x53, 0x15, 0x69, 0x43, 0x43, 0x22, 0x8d, 0x6a, 0xef, 0x8c, 0xc7, 0x8c, 0x44,
		0x3d, 0x45, 0x53, 0xd8, 0xe9, 0xcf, 0xec, 0x68, 0x15, 0xeb, 0xad, 0xc4, 0x0a, 0x9f, 0xfd, 0x04,
		0x57, 0x64, 0x64, 0x68, 0xc4, 0x4a, 0x5e, 0x28, 0xd3, 0xe5, 0x92, 0x46, 0xf4, 0x29, 0xf1, 0xac,
		0xbd, 0x07, 0x94, 0x35, 0x16, 0x5c, 0x64, 0x32, 0xb5, 0x32, 0xe8, 0x28, 0x34, 0xda, 0x58, 0x1b,
		0x51, 0xe6, 0x40, 0x75, 0x7e, 0x87, 0x45, 0xde, 0x70, 0x57, 0x27, 0x26, 0x5a, 0x00, 0x98, 0xb1,
		0x5a, 0x79, 0x25, 0x01, 0x7b, 0x9f, 0xdd, 0x3e, 0xd7, 0x2a, 0x91, 0xa2, 0x22, 0x86, 0xf9, 0x84,
		0xbb, 0x44, 0xe2, 0x53, 0x78, 0xc7, 0x31, 0x23, 0xa5, 0xf3, 0x2f, 0x73, 0xcd, 0xb6, 0xe5, 0x17,
		0x72, 0xe9, 0xdd, 0x74, 0x16, 0xbc, 0xf4, 0x5b, 0x75, 0x5d, 0xba, 0xa8, 0x8e, 0x4a, 0x40, 0x43,
	};
	uint8_t **block_ = new uint8_t*[BLOCK_COUNT];
	
	for (int i = 0; i < BLOCK_COUNT; i++)
	{
		block_[i] = new uint8_t[BlockLengthInBytes];

		generateRandomBytes(block_[i], sizeof block_[i]);

		encryptBlockWithGost15(roundKeys_, block_[i]);
	}

	std::ofstream fout("data.bin", std::ios::binary);

	for (int i = 0; i < BLOCK_COUNT; i++)
	{
		fout.write((char*)block_[i], BlockLengthInBytes);
	}

	fout.close();
}

int main() {
    std::cout << "  ----------------------------------------------------------------------------  " << std::endl;
    std::cout << "    operation                                 performance              " << std::endl;
    std::cout << "  ----------------------------------------------------------------------------  " << std::endl;

	//benchmarkEncryption1();
    //benchmarkEncryption(defaultDuration);
    //benchmarkDecryption(defaultDuration);
	Enc();

    std::cout << "  ----------------------------------------------------------------------------  " << std::endl;
	getchar();
    return 0;
}
