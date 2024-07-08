import pihole6

hole = pihole6.PiHole6('192.168.1.1','http',8085,'')
hole.auth()
print(hole.session)