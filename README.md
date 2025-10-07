# Router-dataplane

Acest proiect se ocupa de implementarea dataplane-ului unui router software, 
responsabil de dirijarea pachetelor de date in functie de o tabela de rutare 
statica.

1. Procesul de dirijare (Forwarding)
Tabela de rutare este incarcata la inceput dintr-un fisier si stocata intr-un 
trie binar.

Fiecare pachet IP primit este verificat:
    - Daca este destinat routerului - se verifica daca este un ICMP Echo Request.
    - Daca trebuie redirectionat - se cauta ruta optima in trie.

Daca nu se gaseste o ruta potrivita - se genereaza un ICMP Destination 
Unreachable.


2. IPv4 – Procesarea pachetelor IP
Verificarea validitatii pachetului (checksum IP, dimensiune, MAC destinatie).

Verificare TTL: daca TTL ≤ 1 → se trimite ICMP Time Exceeded.

Actualizarea TTL si recalcularea checksum-ului.

Determinarea urmatorului hop si verificarea adresei MAC din cache-ul ARP.


3. ARP – Address Resolution Protocol
Implementare ARP Cache pentru maparea IP -> MAC.

Trimitere ARP Request daca MAC-ul nu este cunoscut.

Tratare ARP Reply si actualizarea cache-ului.

Coada pending_packets gestioneaza pachetele blocate pana la obtinerea MAC-ului.


4. ICMP – Internet Control Message Protocol
Procesare ICMP Echo Request primit de catre router si trimiterea unui ICMP Echo
Reply.

Generare de pachete ICMP de eroare pentru cazuri:
    - Destinatie inexistenta (type 3, code 0).
    - TTL expirat (type 11, code 0).

Construirea completa a pachetului ICMP + IP + Ethernet.
