runserver:
	g++ -pthread server.cpp -o server
	./server
runclient:
	g++ -pthread client.cpp -o client
	./client