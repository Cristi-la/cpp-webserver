// Wspracie funkcjonalności serwera webowego
// Server może otrzymywać/parsować zapytanie HTTP (metody, nagłówki, ciało)
// Server może generować/wysyłać odpowiedzi z specyficznymi statusami, nagłówkami ciałami
// Graceful shutdown dzięki sygnałowi SIGINT
// Serwer tworzy plik z logami

// Funkcjonalności GET
// - Serwowanie plików statycznych
// - Indeksowanie katalogów - w przypadku gdy żądana ścieżka to katalog server spróbuje zaserwować plik index.html (jeśli takowy istnieje) z podanego katalogu
// - Serwowanie różnych typów plików - Obsługa MIME type
// - Obsługa parametrów zapytania - ?name=value&name1=valueX

// Funkcjonalności POST
// - Procesowanie danych formularza - serwer radzi sobie z przesłaniem zakodowanymi danymi `application/x-www-form-urlencoded`
// - Procesowanie danych JSON - `application/json`

// Funkcjonalności Protokołu HTTP
// - Zwracaie kodu stanu
// - serwer obsługuje zwracanie odstawowych nagłówków HTTP (`Content-Type`, `Content-Length`)


#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unordered_map>
#include <jsoncpp/json/json.h> 
#include <algorithm>
#include <csignal>
#include <poll.h>

using std::string;
using std::unordered_map;
using std::ifstream;
using std::ostringstream;
using std::istringstream;
using std::ofstream;
using std::cout;
using std::cerr;
using std::endl;

// ofstream jest częścią nagłówka <fstream> i umożliwia strumieniowe 
// operacje wyjściowe na plikach.
ofstream log_file;
bool running = true;
int server_fd;

void log_message(const string &message) {
    std::cout << message << std::endl;
    log_file << message << std::endl;
}

void log_request(const string& client_ip, const string& method, const string& path, const string& version) {
    log_message("Request from " + client_ip + ": " + method + " " + path + " " + version);
}

// graceful shutdown
void handle_signal(int signal) {
    if (signal == SIGINT) {
        log_message("Received SIGINT. Shutting down gracefully...");
        running = false;
        close(server_fd);
    }
}

// tworzy, konfiguruje i uruchamia gniazdo serwera TCP na określonym porcie.
int create_server_socket(int port) {
    sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    // zwraca deskryptor na gniazdo
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        // Sprawdza, czy socket zwróciło poprawny deskryptor gniazda

        // AF_INET: Oznacza, że gniazdo używa IPv4.
        // SOCK_STREAM: Oznacza, że gniazdo jest typu strumieniowego, czyli używa protokołu TCP.
        perror("socket failed");
        exit(EXIT_FAILURE);
        // EXIT_FAILURE to makro zdefiniowane w standardowej bibliotece C,
        // które reprezentuje kod błędu zwracany przez program, gdy kończy 
        // się on niepowodzeniem. Wartość tego makra 
        // jest zdefiniowana w nagłówku <stdlib.h>
    }

    // Ustawia opcje gniazda
    // SOL_SOCKET - Opcje na poziomie gniazda ogólnie wpływają na zachowanie gniazd
    // IPPROTO_IP - Opcje specyficzne dla protokołu IP (IPv4): TTLm MULTICAST
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        // &opt - wskazik do wartości opcji którą checmy ustawić
        // setsockopt nie może wiedzieć z góry, jaki typ danych będzie 
        // potrzebny dla danej opcji, dlatego wymaga, abyśmy przekazali 
        // wskaźnik na odpowiedni typ danych
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    // SO_REUSEADDR: Pozwala na ponowne użycie adresu (jeśli gniazdo było wcześniej zamknięte).
    // SO_REUSEPORT: Pozwala na ponowne użycie portu przez wiele procesów 
    // SO_KEEPALIVE: mechanizm keep-alive, który okresowo sprawdza, czy połączenie jest aktywne.
    // SO_BROADCAST: Umożliwia wysyłanie i odbieranie datagramów broadcast.
    // 

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;

    // Ustawia port na wartość przekazaną do funkcji, 
    // konwertując go z formatu hosta do formatu sieciowego
    address.sin_port = htons(port);
    // Konwersja z little-endian/big-endian


    // przypisuje lokalny adres IP i numer portu do gniazda. 
    if (bind(server_fd, (sockaddr *)&address, sizeof(address)) < 0) {
        // Jeśli bind zwraca -1, oznacza to, że przypisanie adresu nie powiodło się.
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Ustawia gniazdo w tryb nasłuchiwania, co pozwala serwerowi 
    // przyjmować połączenia przychodzące
    // 3 - Maksymalna liczba połączeń, które mogą być w kolejce oczekujących na akceptację.
    if (listen(server_fd, 3) < 0) {
        // funkcja zwraca -1: Wystąpił błąd
        perror("listen");
        exit(EXIT_FAILURE);
        // Może to być kod błędu ECONNREFUSED (połączenie odrzucone).
        // Klienci, którzy próbują nawiązać połączenie, mogą 
        // wejść w stan oczekiwania 
        // (zależnie od implementacji klienta i ustawień sieciowych)
        

        // W przypadku protokołu TCP, jeśli nowe połączenie nie jest akceptowane, 
        // klient TCP może ponowić próbę połączenia (retransmisja SYN).
    }

    return server_fd;
}

// MIME type
// onst string - stały wskaźni
string get_mime_type(const string& extension) {
    // static oznacza, że zmienna mime_types jest lokalna dla funkcji 
    // get_mime_type i zostanie zainicjalizowana tylko raz
        // Dzięki temu, przy kolejnych wywołaniach funkcji, 
        // nie będzie konieczne ponowne tworzenie tej mapy,
    static const unordered_map<string, string> mime_types = {
        // unordered_map - haszowana mapa (słownik) - szybkie wyszukiwanie
        {".html", "text/html"},
        {".htm", "text/html"},
        {".css", "text/css"},
        {".js", "application/javascript"},
        {".json", "application/json"},
        {".png", "image/png"},
        {".jpg", "image/jpeg"},
        {".jpeg", "image/jpeg"},
        {".gif", "image/gif"},
        {".txt", "text/plain"},
        {".pdf", "application/pdf"}
        // MIME (Multipurpose Internet Mail Extensions)
        // - standard używany do opisywania typu pliku 
    };
    // pozwala kompilatorowi automatycznie określić typ zmienne
    auto it = mime_types.find(extension);

    // Sprawdzam czy iterator it nie wskazuje na koniec mapy 
    if (it != mime_types.end()) {
        // Jeśli klucz został znaleziony, 
        // funkcja zwraca wartość z mapy odpowiadającą temu kluczow
        return it->second;
    }

    // używany jako domyślny typ dla danych binarnych
    return "application/octet-stream";
}

string get_status_message(int status_code) {
    static const unordered_map<int, string> status_messages = {
        {200, "OK"},
        {400, "Bad Request"},
        {403, "Forbidden"},
        {404, "Not Found"},
        {405, "Method Not Allowed"},
        {500, "Internal Server Error"},
        {501, "Not Implemented"}
    };
    auto it = status_messages.find(status_code);
    if (it != status_messages.end()) {
        return it->second;
    }
    return "Unknown Status";
}

string generate_response(int status_code, const string& content, const string& content_type = "text/html") {
    string status_message = get_status_message(status_code);
    return "HTTP/1.1 " + std::to_string(status_code) + " " + status_message + "\nContent-Type: " + content_type + "\nContent-Length: " + std::to_string(content.size()) + "\n\n" + content;
}

string read_file(const string& path) {
    // struktura używana do przechowywania informacji o pliku lub katalogu
    struct stat path_stat;

    // path.c_str() - Konwertuje obiekt typu string na wskaźnik typu const char*
    // - wymagany przez stat
    // &path_stat: Wskaźnik na strukturę stat, gdzie zostaną zapisane informacje o pliku.
    // stat - sprawdza atrybuty pliku określonego przez ścieżkę path.
    if (stat(path.c_str(), &path_stat) != 0) {
        return generate_response(404, "404 Not Found");
    }

    // Macro sprawdza czy st_mode ze struktury stat wskazuje, że ścieżka jest katalogiem.
    if (S_ISDIR(path_stat.st_mode)) {
        string index_path = path + "/index.html";

        // klasa - umożliwia strumieniowe odczytywanie danych z plików.
        // domyślny tryb otwierania pliku za pomocą ifstream file(index_path); to tryb tekstowy
        ifstream file(index_path);
        if (!file.is_open()) {
            return generate_response(404, "404 Not Found");
        }

        // Odczytuje zawartość pliku do zmiennej 
        // istreambuf_iterator jest szablonem klasy, który jest zdefiniowany dla typu char
        // działa bezpośrednio na buforze strumienia wejściowego 
        // minimalizuje liczbę operacji wejścia/wyjścia.
        string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        return generate_response(200, content);
    }

    // Otwieranie pliku w trybie binarnym
    // W tym trybie dane są odczytywane dokładnie takie, jakie są w pliku, bez żadnych konwersji znaków
    ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return generate_response(404, "Not Found");
    }

    string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    string extension = path.substr(path.find_last_of('.'));
    string mime_type = get_mime_type(extension);

    return generate_response(200, content, mime_type);
}

string handle_get(const string& path) {
    string file_path = path == "/" ? "index.html" : path.substr(1); 
    return read_file(file_path);
}

string handle_post(const string& request) {

    // \r\n\r\n - znacza koniec nagłówków HTTP i początek treści (ciała) żądania.
    std::size_t body_pos = request.find("\r\n\r\n");
    if (body_pos == string::npos) {
        // Sprawdza, czy sekwencja została znalezion
        return generate_response(400, "Bad Request");
    }
    //  Wyodrębnianie treść żądania (ciało)
    string body = request.substr(body_pos + 4);

    std::size_t content_type_pos = request.find("Content-Type:");
    string content_type;

    // Sprawdza, czy nagłówek Content-Type został znaleziony.
    if (content_type_pos != string::npos) {
        std::size_t end_pos = request.find("\r\n", content_type_pos);
        content_type = request.substr(content_type_pos + 13, end_pos - content_type_pos - 13);
        
        // erase - służy do usuwania znaków lub zakresów znaków z ciągu znaków.
        content_type.erase(std::remove(content_type.begin(), content_type.end(), ' '), content_type.end());

        // std::remove - nie usuwa fizycznie elementów z kontenera, 
        //              ale przesuwa wszystkie elementy, które mają być usunięte, 
        //              na koniec kontenera, a następnie zwraca iterator wskazujący 
        //              na nową końcową pozycję zakresu, który nie zawiera tych elementów.
    }

    string response_body;
    if (content_type == "application/x-www-form-urlencoded") {
        response_body = "Received form data:\n" + body;
    } else if (content_type == "application/json") {
        Json::Value root;
        Json::CharReaderBuilder reader;
        string errs;
        istringstream s(body);
        if (Json::parseFromStream(reader, s, &root, &errs)) {
            response_body = "Received JSON data:\n" + root.toStyledString();
        } else {
            response_body = "Invalid JSON data";
        }
    } else {
        response_body = "Received POST data:\n" + body;
    }

    return generate_response(200, response_body, "text/plain");
}



void handle_request(int new_socket, const sockaddr_in& client_addr) {
    // new_socket - Deskryptor nowego gniazda połączenia przychodzącego
    // client_addr - przechowuje informacje o adresie klienta.

    // Inicjalizuje bufor
    char buffer[30000] = {0};
    read(new_socket, buffer, 30000);

    // Konwertuje bufor buffer na obiekt typu string
    string request(buffer);

    // strumień wejściowy na podstawie ciągu request.
    istringstream request_stream(request);
    string method, path, version;

    // Parsuje pierwszą linię żądania HTTP, która zawiera metodę, ścieżkę i wersję.
    request_stream >> method >> path >> version;

    // Inicjalizuje tablicę znaków do przechowywania adresu IP klienta
    char client_ip[INET_ADDRSTRLEN];

    // Konwertuje adres IP klienta z formatu binarnego do tekstowego.
    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    log_request(client_ip, method, path, version);

    // Parsowanie Parametrów Zapytania
    // size_t - unsigned integer #include <cstddef>
    std::size_t query_pos = path.find('?');
    if (query_pos != string::npos) {
        string query = path.substr(query_pos + 1);
        path = path.substr(0, query_pos);
        log_message("Query: " + query);
    }

    string response;
    if (method == "GET") {
        response = handle_get(path);
    } else if (method == "POST") {
        response = handle_post(request);
    } else {
        response = generate_response(405, "Method Not Allowed");
    }

    // Wysyła odpowiedź HTTP z gniazda new_socket.
    send(new_socket, response.c_str(), response.size(), 0);
    close(new_socket);
}

int main() {
    // Port na którym będzie nasłuchiwał serwer
    // Inicjalizacja zmiennej
    int port = 8080;


    // Funkcja odpowiada za utworzenie gniazda serwera
    // Zwraca deskryptor
    server_fd = create_server_socket(port);


    // Deklaracja zmiennych
    // Deskryptor pliku dla nowo zaakceptowanego połączenia.
    int new_socket;
    

    // Struktura zdefiniowana w <netinet/in.h>
    // używana do opisywania adresów internetowych (IPv4)
    // przechwoująca informacje o adresie serwera.
    sockaddr_in address, client_addr; 
    // dla ipv6 --> sockaddr_in6 
    // client_addr - adres klienta
    // address - adres serwera


    // Struktura zdefiniowana w nagłówku <sys/socket.h>
    // używany do reprezentowania długości struktur adresowych 
    // w wywołaniach systemowych związanych z gniazdami sieciowymi
    socklen_t client_addrlen = sizeof(client_addr);
    // -  Długość struktury jest przekazywana, aby funkcja accept 
    //    wiedziała, ile bajtów może bezpiecznie odczytać i zapisać 
    //    do struktury adresowej.

    // Open log file
    // std::ios::out: Otwiera plik do zapisu. Jeśli plik nie istnieje, zostanie utworzony.
    // std::ios::app: Otwiera plik w trybie dopisywania. Wszystkie dane będą dopisywane na końcu pliku
    // std::ios::in: Otwiera plik do odczytu.
    // std::ios::binary: Otwiera plik w trybie binarnym.
    // std::ios::ate: Otwiera plik i ustawia wskaźnik na koniec pliku.
    // std::ios::trunc: Otwiera plik i opróżnia jego zawartość, jeśli plik istnieje.
    log_file.open("server.log", std::ios::out | std::ios::app);

    // Sprawdza, czy plik został poprawnie otwarty. 
    if (!log_file.is_open()) {
        // cerr to predefiniowany obiekt strumienia w C++ używany do wyświetlania komunikatów o błędach
        // biblioteka <iostream>
        cerr << "Failed to open log file" << endl;
        return 1;
    }


    // Ustawia funkcję obsługi sygnału dla sygnału. 
    // Sygnał SIGINT jest wysyłany do procesu, gdy użytkownik naciśnie Ctrl+C.
    signal(SIGINT, handle_signal);
    // SIGTERM (Termination) - Żądanie zakończenia procesu
    // SIGKILL - Natychmiastowe zakończenie procesu
    // SIGQUIT - Zakończenie procesu i wygenerowanie core dump

    
    // Deklaruje tablicę znaków
    // używana do przechowywania nazwy hosta 
    char hostbuffer[256];

    // to struktura zdefiniowana w nagłówku <netdb.h>, 
    // używana do przechowywania informacji o adresach sieciowych.
    addrinfo hints, *info, *p;
    // hints --> Używany do ustawienia kryteriów wyszukiwania dla funkcji getaddrinfo.
    // info --> Wskaźnik na początek listy wyników zwróconych przez getaddrinfo.
    // p --> Używany do iteracji po wynikach zwróconych przez getaddrinfo.


    // używana do przechowywania kodu wynikowego zwróconego przez funkcję getaddrinfo
    int gai_result;

    if (gethostname(hostbuffer, sizeof(hostbuffer)) == -1) {
        // Funkcja gethostname zwraca 0 w przypadku powodzenia.
        // wypisuje komunikat o błędzie na standardowe wyjście błędów
        perror("gethostname");
        // Zwraca "gethostname" i opisu błędu powiązanego z wartością errno. 
        // errno jest zmienną globalną ustawianą przez 
        //    funkcje systemowe i biblioteczne w przypadku wystąpienia błędu.
        return 1;
    }


    // funkcja ta jest używana do wyzerowania struktury
    memset(&hints, 0, sizeof(hints));
    // Chodzi o to, aby upewnić się, że wszystkie pola struktury 
    // hints są zainicjalizowane wartościami domyślnymi, 
    // zanim zostaną ustawione specyficzne wartości

    // Z nagłówka <sys/socket.h>
    // oznacza, że getaddrinfo powinna zwrócić adres IPv4
    hints.ai_family = AF_INET;
    // ipv6 --> AF_INET6

    // Z nagłówka <sys/socket.h>
    // powinna zwrócić gniazda typu strumieniowego, które są używane do połączeń TCP
    // połaczenie 2 kierunkowe, bez duplikatów w kolejności
    hints.ai_socktype = SOCK_STREAM;
    // SOCK_RDM  -->  bez ustalania kolejności
    // SOCK_DGRAM --> Niezawodne połączenie datagramowe (UDP)


    // wskazuje, że funkcja getaddrinfo powinna zwrócić kanoniczną nazwę hosta w polu
    // z nagłówku <netdb.h>
    hints.ai_flags = AI_CANONNAME; // FQDN 
    // AI_PASSIVE --> adres jest używany do nasłuchiwania na połączenia przychodzącego
    // AI_NUMERICHOST --> Wymaga, aby nazwa hosta była adresem numerycznym


    // uzyskać informacje o adresach sieciowych związanych z nazwą host
    // nullptr: Port lub usługa, którą ignorujemy w tym przypadku.
    // &hints - Wskaźnik do struktury addrinfo
    // &info - Wskaźnik na wskaźnik do listy wyników
    if ((gai_result = getaddrinfo(hostbuffer, nullptr, &hints, &info)) != 0) {
        cerr << "getaddrinfo: " << gai_strerror(gai_result) << endl;
        return 1;
    }

    // Iteracja po wynikach
    // Ustawia wskaźnik p na początek listy wyników
    for (p = info; p != nullptr; p = p->ai_next) {
        void *addr;
        string  ipver;  
        // Tablica znaków do przechowywania adresu IP w postaci tekstowej
        char ipstr[INET6_ADDRSTRLEN];

        // Sprawdzenie rodziny adresów
        //  "->" używane do dostępu do członków struktury lub klasy za pośrednictwem wskaźnika
        if (p->ai_family == AF_INET) {
            // Ponieważ ai_addr jest typu sockaddr *, musimy rzutować go na odpowiedni 
            sockaddr_in *ipv4 = (sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
            ipver = "IPv4";
        } else {
            sockaddr_in6 *ipv6 = (sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            //  Kiedy rzutujemy literał łańcuchowy na char *, informujemy kompilator
            // że chcemy traktować wskaźnik do const char
            ipver = "IPv6";
        }

        // jest używana do konwersji adresów sieciowych z formatu binarnego do formatu tekstowego
        inet_ntop(p->ai_family, addr, ipstr, sizeof(ipstr));
        log_message("Server running on " + ipver + ": " + string(ipstr) + " Port: " + std::to_string(port));
    }

    // Zwalnia pamięć przydzieloną przez getaddrinfo.
    freeaddrinfo(info);


    // Deklaruje tablicę fds jednego elementu typu pollfd
    pollfd fds[1];
    // Ustawia deskryptor pliku na server_fd, co oznacza, 
    // że będziemy monitorować ten deskryptor (gniazdo serwera)
    // pod kątem zdarzeń I/O.
    fds[0].fd = server_fd;

    // stawia zdarzenia do monitorowania na POLLIN,
    // co oznacza, że chcemy sprawdzić, czy jest dostępne dane do odczytu 
    fds[0].events = POLLIN;
    // POLLIN: Sprawdza, czy jest dostępne dane do odczytu.
    // POLLOUT: Sprawdza, czy można zapisać dane.
    // POLLERR: Sprawdza, czy wystąpiły błędy

    while (running) {
        // monitoruje tablicę fds z jednym elementem przez 1000 milisekund
        int poll_count = poll(fds, 1, 1000);

        // Funkcja poll blokuje się do momentu, gdy jedno z 
        // monitorowanych zdarzeń wystąpi lub upłynie czas oczekiwania (timeout).
        if (poll_count == -1) {
            // poll_count --> rzechowuje liczbę deskryptorów plików, dla których wystąpiły zdarzenia.
            if (errno == EINTR) {
                break; // Interrupted by signal
            }
            perror("poll");
            break;
        }

        // Sprawdza czy poll zwróciło jakiekolwiek zdarzenia do obsługi
        if (poll_count > 0) {
            // Sprawdz czy odpowiednie zdarzenie wystapilo
            if (fds[0].revents & POLLIN) {

                // Akceptuje nowe połączenie przychodzące.
                if ((new_socket = accept(server_fd, (sockaddr *)&client_addr, &client_addrlen)) < 0) {
                    if (running) {
                        perror("accept");
                    }
                    break;
                }
                handle_request(new_socket, client_addr);
            }
        }
    }

    log_message("Server shut down.");
    log_file.close();

    // używana do zamykania deskryptorów plików
    close(server_fd);
    return 0;
}
