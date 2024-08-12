/*
 * Copyright (C) 2018-2022 David C. Harrison. All right reserved.
 *
 * You may not use, distribute, publish, or modify this code without 
 * the express written permission of the copyright holder.
 */

#include <iostream>
#include <string.h> 
#include <string> 
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <vector> 
#include <queue> 
#include <thread>
#include <mutex> 
#include <vector> 
#include <ctype.h>
#include <crypt.h>
#include "cracker.h"

int create_multicast_listen() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) { exit(-1); }
    struct sockaddr_in server_addr;
    bzero((char *) &server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; 
    server_addr.sin_port = htons(get_multicast_port());
    if (bind(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) exit(-1);
    struct ip_mreq multicastRequest;
    multicastRequest.imr_multiaddr.s_addr = get_multicast_address();
    multicastRequest.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *) &multicastRequest, sizeof(multicastRequest)) < 0) exit(-1);
    return sockfd; 
}

void recieve_broadcast(int sockfd, Message &msg) {
    int n = recvfrom(sockfd, &msg, sizeof(msg), 0, NULL, 0);
    if (n < 0) { std::cout << "1" << std::endl; exit(-1); }
    char hostString[6];
    gethostname(hostString, 6);
    std::cout << "Recieved message on " << hostString << ": " << std::endl;
}

void print(Message msg) {
    std::cout << "\talphabet: " << msg.alphabet << std::endl; 
    std::cout << "\tcruzid: " << msg.cruzid << std::endl; 
    std::cout << "\tnum_passwds: " << ntohl(msg.num_passwds) << std::endl;
    for (unsigned int i=0; i < ntohl(msg.num_passwds); ++i) {
        std::cout << "\t\t" << msg.passwds[i] << std::endl; 
    }
    std::cout << "\thostname: " << msg.hostname << std::endl;
    std::cout << "\tport: " << ntohs(msg.port) << std::endl; 
}

void crack_threaded(std::string initial, Message &msg, std::vector<std::string> &passwords, std::mutex &passLock) {
    char pass[5];
    pass[0] = initial[0];
    pass[1] = initial[1];
    struct crypt_data data;
    data.initialized = 0;
    int alphaLen = strlen(msg.alphabet); 
    for (int i=0; i < alphaLen; ++i) {
        for (int j=0; j < alphaLen; ++j) {
            pass[2] = msg.alphabet[i];
            pass[3] = msg.alphabet[j]; 
            for (int l = 0; l < (int) ntohl(msg.num_passwds); l++) {
                char salt[3] = {};
                salt[0] = msg.passwds[l][0];
                salt[1] = msg.passwds[l][1];
                char *guessHash = crypt_r(pass, salt, &data); 
                if (strcmp(guessHash, msg.passwds[l]) == 0) { 
                    std::cout << "\tPASSWORD FOUND: " << pass + std::to_string(l) << std::endl;
                    passLock.lock();
                    passwords.push_back(pass + std::to_string(l));
                    passLock.unlock(); 
                }
            }
        }
    }
}

void enqueue_permutations(std::queue<std::string> &charQueue, Message &msg, char *hostString) {
    int start = 0;
    if (strcmp(hostString, "olaf") == 0) { start = 0;}
    if (strcmp(hostString, "thor") == 0) { start = 1;}
    if (strcmp(hostString, "nogbad") == 0) { start = 2;}
    if (strcmp(hostString, "noggin") == 0) { start = 3;}
    for (int i=0; i < ALPHABET_LEN; i++) {
        for (int j = start; j < ALPHABET_LEN; j+=4) {
            char initial[3];
            initial[0] = msg.alphabet[i];
            initial[1] = msg.alphabet[j];
            charQueue.push(initial); 
        }
    }
}

void recieve_passwords(int sockfd, Message &msg, int missing) {
    char buffer[256];
    int recieves = 0; 
    for (;;) {
        int n = recvfrom(sockfd, &buffer, sizeof(buffer), 0, NULL, 0);
        if (n < 0) { std::cout << "1" << std::endl; exit(-1); }
        if (n > 32) { continue; }
        std::cout << "Recieved message ... " << std::endl;
        std::cout << "\tstoring " << buffer << " at index " << buffer[4] - '0' << std::endl;
        memset(msg.passwds[buffer[4] - '0'], 0, sizeof(msg.passwds[buffer[4] - '0'])); 
        strncpy(msg.passwds[buffer[4] - '0'], buffer, 4);
        recieves++;
        if (recieves == missing) { return; }
    } 
}

void broadcast_passwords(std::vector<std::string> &passwords) {
    // CREATE UDP SOCKET CONNECTION WITH SERVERS
	int port = 2212;
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		std::cout << "1" << std::endl;
		exit(-1);
	}
	int ttl = 1;
	if (setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, (void *) &ttl, sizeof(ttl)) < 0) {
		std::cout << "2" << std::endl;
		exit(-1); 
	}
	struct sockaddr_in multicastAddr;
	memset(&multicastAddr, 0, sizeof(multicastAddr));
	multicastAddr.sin_family = AF_INET;
	multicastAddr.sin_addr.s_addr = inet_addr("224.0.0.116");
	multicastAddr.sin_port = htons(port);
	for (std::string &password : passwords) {
        std::cout << "sending " << password << " ... " << std::endl; 
        int n = sendto(sockfd, password.c_str(), sizeof(password), 0, (struct sockaddr *) &multicastAddr, sizeof(multicastAddr));
        if (n < 0) { std::cout << "3" << std::endl; exit(-1); }
        std::cout << n << " bytes sent " << std::endl; 
    }
    close(sockfd); 
}

// send TCP response from OLAF to SERVER
void reply(Message &msg) {
    // CREATE CLIENT CONNECTION
    int clientfd = socket(AF_INET, SOCK_STREAM, 0); 
    struct hostent *server = gethostbyname(msg.hostname);
    struct sockaddr_in serv_addr;
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = (msg.port);
    int n = connect(clientfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
    if (n < 0) { std::cout << "connect() failure: port = " << htons(msg.port) << " host = " << (char *)server->h_addr << std::endl; exit(-1); }

    n = send(clientfd, &msg, sizeof(msg), 0);
    if (n < 0) { std::cout << "send() failure" << std::endl; exit(-1); }
    close(clientfd);
}

int main(int argc, char *argv[]) {
    // Supress unused variable compiler warnings
    (void) argc;
    (void) argv; 

    Message msg;
    int sockfd = create_multicast_listen(); 
    char hostString[6];
    gethostname(hostString, 6);
    std::vector<std::string> passwords;

    while (true) {
        recieve_broadcast(sockfd, msg);
        print(msg); 
        if (strcmp(msg.cruzid, "cepetrie") != 0) { continue; }
	    
        std::queue<std::string> charQueue;
        std::mutex passLock;  
        enqueue_permutations(charQueue, msg, hostString); 

        // Multithreading ... 
        std::mutex queueLock;
        auto lambdaCrack = [&]() {
            while (true) {
                queueLock.lock();
                if (charQueue.empty()) {
                    queueLock.unlock();
                    return;
                }
                std::string first = charQueue.front();
                charQueue.pop();
                queueLock.unlock();
                crack_threaded(first, msg, passwords, passLock);
            }
        };
        std::vector<std::thread> threads;
        for (unsigned int i=0; i < 24; ++i) {
            std::thread t{lambdaCrack}; 
            threads.push_back(std::move(t)); 
        }
        for (auto &thread : threads) {
            thread.join(); 
        }
        std::cout << "MAIN ITERATION COMPLETED" << std::endl; 
        break;
    }

    // FORWARD PASSWORDS TO OLAF TO FORMAT TCP RESPONSE TO TESTING SERVER
    if (strcmp(hostString, "olaf") == 0) {
        std::cout << std::endl << "HERE IS WHERE OLAF WOULD FORMAT TCP RESPONSE" << std::endl;
        for (std::string &password : passwords) {
            memset(msg.passwds[password[4] - '0'], 0, sizeof(msg.passwds[password[4] - '0'])); 
            strncpy(msg.passwds[password[4] - '0'], password.c_str(), 4);
        }
        recieve_passwords(sockfd, msg, ntohl(msg.num_passwds) - passwords.size());
        close(sockfd); 
        print(msg); 
        reply(msg);
    } else {    
        close(sockfd); 
        broadcast_passwords(passwords); 
    }
    return 0; 
}
