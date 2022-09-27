#include <iostream>
#include <string>
#include <vector>
#include <string>
#include <bitset>
#include <random>
#include <array>
#include <fstream>
#include <iomanip>
#include <ctime>

#define N 24
#define FRAME_SIZE 8
#define FRAME_INFO 2
// Кодируемое число: AAFF3C
std::array<int, 2> active_bytes = {3, 4};
std::array<std::string, 4> HEAD_INDICATOR = {"00000000", "00000000", "00000000", "00000000"};
std::array<std::string, 4> TAIL_INDICATOR = {"11111111", "11111111", "11111111", "11111111"};

int package_analyser(std::string data_path)
{
    // Функция считывает данные с файла и расшифровывает их согласно протоколу
    int package_number = 0;
    int package_size = 0;
    std::vector<int> frames_data;
    int check_control_sum{0};
    std::string useful_data; // Массив для получения полезных данных
    std::ifstream fin;
    fin.open(data_path);
    if (!fin.is_open()) {
        throw false;
    }
    std::string str;
    int state = 0;
    while (!fin.eof()){
        switch (state)
        {
            case 0:
                fin >> str;
                if (str == HEAD_INDICATOR[0]){
                    state = 1;
                } else {
                    state = 0;
                }
                break;
           case 1:
                fin >> str;
                if (str == HEAD_INDICATOR[1]){
                    state = 2;
                } else {
                    state = 0;
                }
                break;
            case 2:
                fin >> str;
                if (str == HEAD_INDICATOR[2]){
                    state = 3;
                } else {
                    state = 0;
                }
                break;
            case 3:
                fin >> str;
                if (str == HEAD_INDICATOR[3]){
                    state = 4;
                } else {
                    state = 0;
                }
                break;
            case 4:
            fin >> str; // Получаем номер пакета
            package_number = stoi(str, 0, 2);
            fin >> str; // Получаем размер пакета
            package_size = stoi(str, 0, 2);
            // Если программа дошла до этой точки, то был обнаружен head
                // Здесь происходит считывание кадров
                for (int i = 0; i < 12; i++) {
                    std::string buffer;
                    fin >> buffer;
                    if (buffer.size() != 8) {
                        throw "Frame size must be " + std::to_string(FRAME_SIZE) + ".";
                    }
                    else if (!std::stoi(buffer, 0, 2)) {
                        throw "Incorrect data type.";
                    }
                    else if (fin.eof()) {
                        throw "End of source data file reached";
                        // Остальные проверки на возможность досрочного перехода к крайним пакетам
                        // опустим, поскольку ошибка всплывет на этапе проверки контрольной суммы
                    } else {
                        useful_data += buffer[active_bytes[0]];
                        useful_data += buffer[active_bytes[1]];
                        frames_data.push_back(std::stoi(buffer, 0, 2));
                    }

                }
                state = 5;
                break;

            case 5:
            // Проверка контрольной суммы:
                fin >> str;
                // Проверим полезные данные:
                for (auto i: frames_data) {
                    std::cout << i << "\t";
                }
                std::cout << std::endl;

                std::cout << "CheckSumString: " << str << std::endl;
                for (int i = 0; i < int(frames_data.size()); i ++) {
                    if (i == 2 or i == 5 or i == 8 or i == 11) {
                        check_control_sum = check_control_sum ^ frames_data[i];
                    }
                    else if (i == 1 or i == 4 or i == 7 or i == 10) {
                        check_control_sum = check_control_sum & frames_data[i];
                    }
                    else {
                        check_control_sum = check_control_sum || frames_data[i];
                    }
                }

                if (std::bitset<FRAME_SIZE>(check_control_sum).to_string() != str){
                    std::cout << std::bitset<FRAME_SIZE>(check_control_sum).to_string() << std::endl;
                    throw 1;
                }
                state = 6;
                break;
            case 6:
                std::cout << "CheckSum verified!" << std::endl;
                fin >> str; // Получим кадр с зашифрованной служебной информацией (размер, номер)
                if (std::stoi(str, 0, 2) == (package_number ^ package_size)) {
                    state = 7;
                } else {
                    throw 2;
                }
                break;

            case 7:
                fin >> str;
                if (str == TAIL_INDICATOR[0]){
                    state = 8;
                } else {
                    throw 3;
                }
                break;
           case 8:
                fin >> str;
                if (str == TAIL_INDICATOR[1]){
                    state = 9;
                } else {
                    throw 3;
                }
                break;
            case 9:
                fin >> str;
                if (str == TAIL_INDICATOR[2]){
                    state = 10;
                } else {
                    throw 3;
                }
                break;
            case 10:
                fin >> str;
                if (str == TAIL_INDICATOR[3]){
                } else {
                    throw 3;
                }
                break;

            default:
                std::cout << "Security case" << std::endl;
            break;
        }
    }
    // Вывод пакета на экран
    std::cout << "PACKAGE: " << useful_data << std::endl;
    return stoi(useful_data, 0, 2);
}

void readDword(std::string& path, std::ifstream& fin, int& x)
{
    // Функция чтения шестнадцатибитного слова из файла
    fin.open(path);
    if (!fin.is_open()) {
        throw "Something went wrong while opening file";
    } else {
        std::cout << "File succesfuly opened!" << std::endl;
    }
    fin >> std::hex;
    fin >> x;
    fin >> std::setbase(0);
}

void writeDword(std::string& path, std::ofstream& fout, std::string bits)
{
    std::array<int, 2> active_bytes = {3, 4};
    std::array<int, N/FRAME_INFO> frames_data;
    int PACKAGE_NUMBER = 1;
    fout.open(path);
    if (!fout.is_open()) {
        throw "Something went wrong while opening file";
    } else {
        std::cout << "File succesfuly opened!" << std::endl;
    }
    // Запись открывающих кадров в файл
    for (auto k: HEAD_INDICATOR) {
        fout << k << std::endl;
    }
    // Запись кадра с информацией о пакете (1/2): номер пакета
    std::string head_frame_0 = std::bitset<FRAME_SIZE>(PACKAGE_NUMBER).to_string();
    fout << head_frame_0 << std::endl;
    // Запись кадра с информацией о пакете (2/2): число бит в пакете
    std::string head_frame_1 = std::bitset<FRAME_SIZE>(bits.size()).to_string();
    fout << head_frame_1 << std::endl;
    // Кодируем информацию по следующему принципу:
    // Полезная информация хранится в 4, 5 битах кадра
    // Остальная информация заполняется случайным образом (0 или 1)
    // Отщипывать полезную информацию по 2 бита будем от строки полезных данных bits
    // Для удобства разделим строку на массив
    std::array<int, N> binary_data;
    for (int i = 0; i < N; i ++) {
        binary_data[i] = bits[i];
    }

    int counter {0};
    std::cout << "Writing data to file started:" << std::endl;
    while(counter != N) {
        std::string frame{""};
        for (int j =0; j < FRAME_SIZE; j ++) {
            if (j == active_bytes[0] or j == active_bytes[1]) {
                frame += binary_data[counter];
                counter += 1;
            } else {
                frame += std::to_string(rand() % 2);
            }
        }
        std::cout << "frame: " << frame << std::endl << std::stoi(frame, 0, 2) << std::endl;
        // Запишем данные о кадре в промежуточный массив
        frames_data[(counter / 2) - 1] = std::stoi(frame, 0, 2);

        // Записываем сформированный кадр в файл
        fout << frame << std::endl;
    // Таким образом, 7 - 18 кадры включительно - кадры с полезной информацией
    // Следующим кадром отправим контрольную сумму (сформируем ее по случайному правилу)
    // fout << control_sum_binary;
    }
    int control_sum{0};
    for (int i = 0; i < int(frames_data.size()); i ++) {
        if (i == 2 or i == 5 or i == 8 or i == 11) {
            control_sum = control_sum ^ frames_data[i];
        }
        else if (i == 1 or i == 4 or i == 7 or i == 10) {
            control_sum = control_sum & frames_data[i];
        }
        else {
            control_sum = control_sum || frames_data[i];
        }
    }


    std::cout << "Control sum: " << control_sum << std::endl;
    std::string control_sum_binary = std::bitset<FRAME_SIZE>(control_sum).to_string();
    fout << control_sum_binary << std::endl;

    // Добавим в конец пакета дополнительный кадр проверки номера пакета\числа бит в нем
    fout << std::bitset<FRAME_SIZE>(PACKAGE_NUMBER ^ N).to_string() << std::endl;
    // В конце запишем хвост
    for (auto k: TAIL_INDICATOR) {
        fout << k << std::endl;
    }

    fout.close();
}

int main()
{
    srand(time(NULL));
    int data; // Полезные данные
    std::string data_path = "Data.txt";
    std::string coded_data_path = "CodedData.txt";
    std::ifstream fin;
    readDword(data_path, fin, data);
    std::cout << "Data getted: " << data << std::endl;
    std::string binary = std::bitset<N>(data).to_string();
    std::cout << "Binary wiev: " <<  binary << std::endl;
    // На данном этапе получили представление исходного числа в двоичном виде.
    // Теперь необходимо закодировать данное число согласно определенному протоколу.
    // Протокол будет состоять из 3 частей:
    // head - "голова пакета" - 4 кадра + кадр, содержащий номер пакета
    // tail - "номер пакета" - 4 кадра + кадр, содержащий контрольную сумму
    // Служебный кадр с индексом tail.index() - 1 - содержит контрольную сумму (см. даллее)
    std::ofstream fout;
    writeDword(coded_data_path, fout, binary);
    // Откроем наш файл и расшифруем через package analyser
    try{
        int result = package_analyser(coded_data_path);
        std::cout << "RESULT:" << std::hex << result << std::endl;
    }
    catch (const char *ex) {
        std::cout << "Something went wrong while data getting..." << std::endl;
    }

    catch (bool ex) {
        std::cout << "File was not opened." << std::endl;
    }
    catch (int ex) {
        if (ex == 1) {
            std::cout << "Wrong CheckSum getted." << std::endl;
        }
        else if (ex == 2){
            std::cout << "Async of package." << std::endl;
        }
        else if (ex == 3){
            std::cout << "End of package is damaged" << std::endl;
        }
    }

    return 0;
}




