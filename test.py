import pihole6

hole = pihole6.PiHole6('192.168.1.1','http',8085,'')
hole.auth()
print(hole.session)
stats = hole.api_call('GET', 'stats/summary')
print(stats)
hole.blocking_set(enabled=False,timer=None)
print(hole.blocking_get())
hole.blocking_set(enabled=True,timer=None)
print(hole.blocking_get())