# Firewall

firewall შედგება ორი ქვეპროექტისგან:
1. stateless firewall
2. stateful firewall

მეორე დაფუძნებულია პირველზე. პროექტისთვის საჭიროა წინასწარ გამზადებული VM, რომელიც აქვეა მიმაგრებული.

ტესტირება ხდება შემდეგი წესით (როგორც რეალურ სისტემებშია). ფილტრის კონფიგურაციის ფაილი იქნება სამი დონის წესებისგან შემდგარი:
1. application layer rules;
2. transport layer rules;
3. network layer rules;
ეს კატეგორიები ზევიდან ქვევით უნდა იკითხებოდეს/სრულდებოდეს. ასევე თითოეულ კატეგორიაში წესები დალაგებული იქნება სპეციფურიდან(პირველი) ზოგადისკენ(ბოლო). მაგალითად:

* drop dns mail.google.com
* pass dns google.com
* pass tcp any 80
* pass tcp any 443
* drop tcp any any
* pass udp any 53
* drop udp any any
* drop icmp any 8.8.8.8
* pass icmp any any

requires - Python 2.7