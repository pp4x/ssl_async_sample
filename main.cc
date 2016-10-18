
/* 
 * File:   main.cc
 * Author: paulo
 *
 * Created on 18 October 2016, 14:55
 */

#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <cerrno>
#include <netdb.h>
#include <unistd.h>

const char request[] = "GET / HTTP/1.1\n\rHost:www.google.com\n\r\n\r";

struct SecureSocket
{

	enum class Status
	{
		DISCONNECTED, CONNECTING, SSL_CONNECTING, REQUEST, RESPONSE
	};
	int socket = -1;
	SSL * ssl = nullptr;
	Status status = Status::DISCONNECTED;
};

void main_loop(int efd);

/*
 * 
 */
int main()
{
	addrinfo hint = addrinfo();
	hint.ai_family = AF_INET;
	addrinfo *addr = nullptr;
	getaddrinfo("www.google.com", "443", &hint, &addr);

	int efd = epoll_create1(0);

	SSL_library_init();
	SSL_load_error_strings();

	SSL_CTX * context = SSL_CTX_new(TLSv1_2_client_method());

	SecureSocket sock;
	sock.socket = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	sock.ssl = SSL_new(context);
	SSL_set_fd(sock.ssl, sock.socket);

	epoll_event event;
	event.events = EPOLLIN | EPOLLOUT | EPOLLET;
	event.data.ptr = &sock;
	epoll_ctl(efd, EPOLL_CTL_ADD, sock.socket, &event);

	int err = connect(sock.socket, addr->ai_addr, addr->ai_addrlen);
	if (!err)
	{
		sock.status = SecureSocket::Status::SSL_CONNECTING;
		if ((err = SSL_connect(sock.ssl)) == 1)
			sock.status = SecureSocket::Status::REQUEST;
		else
		{
			err = SSL_get_error(sock.ssl, err);
			if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
			{
				close(sock.socket);
				sock.status == SecureSocket::Status::DISCONNECTED;
			}
		}
	}
	else if (errno == EINPROGRESS)
	{
		sock.status = SecureSocket::Status::CONNECTING;
	}

	freeaddrinfo(addr);

	if (sock.status != SecureSocket::Status::DISCONNECTED)
		main_loop(efd);

	SSL_shutdown(sock.ssl);
	SSL_free(sock.ssl);
	close(sock.socket);
	close(efd);
	return 0;
}

void main_loop(int efd)
{
	const size_t max = 0x100;
	epoll_event events[max];
	bool running = true;
	int n = 0;
	int err = 0;
	char buffer[4096];

	while (running && n > -1)
	{
		n = epoll_wait(efd, events, max, -1);

		for (int i = 0; i < n; ++i)
		{
			auto & event = events[i];
			SecureSocket & sock = *static_cast<SecureSocket*> (event.data.ptr);

			switch (sock.status)
			{
			case SecureSocket::Status::RESPONSE:
				err = SSL_read(sock.ssl, buffer, sizeof buffer);
				if (err > -1)
					std::cout << std::string(buffer, err) << std::endl;
				else
				{
					std::cerr << "Rd Err: " << SSL_get_error(sock.ssl, err) << std::endl;
				}

				running = false;
				break;
			case SecureSocket::Status::CONNECTING:
				sock.status = SecureSocket::Status::SSL_CONNECTING;
				if ((event.events & EPOLLOUT))
				{
					event.events = EPOLLIN | EPOLLET;
					epoll_ctl(efd, EPOLL_CTL_MOD, sock.socket, &event);
					err = SSL_connect(sock.ssl);
					if (err == 1)
						sock.status = SecureSocket::Status::REQUEST;
					else
					{
						if ((err = SSL_get_error(sock.ssl, err)) != SSL_ERROR_WANT_READ)
						{
							std::cerr << "Connect Err: " << err << std::endl;
							ERR_print_errors_fp(stderr);
							sock.status = SecureSocket::Status::DISCONNECTED;
							running = false;
						}
					}
				}
				break;
			case SecureSocket::Status::SSL_CONNECTING:
				err = SSL_connect(sock.ssl);
				if (err == 1)
					sock.status = SecureSocket::Status::REQUEST;
				else if ((err = SSL_get_error(sock.ssl, err)) != SSL_ERROR_WANT_READ)
				{
					std::cerr << "Connect Err: " << err << std::endl;
					ERR_print_errors_fp(stderr);
					sock.status = SecureSocket::Status::DISCONNECTED;
					running = false;
				}
				break;
			}

			if (sock.status == SecureSocket::Status::REQUEST)
			{
				err = SSL_write(sock.ssl, request, sizeof request - 1);
				if (err < 0)
				{
					std::cerr << "Wr Err." << err << std::endl;
					ERR_print_errors_fp(stderr);
					running = false;
				}
				sock.status = SecureSocket::Status::RESPONSE;
			}
		}
	}
}
