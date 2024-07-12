import sys
sys.path.insert(0, './src')
import pihole6

hole = pihole6.PiHole6('192.168.1.1','http',8085,'')
hole.authCheck()
print(hole.session)
result = hole.blockingSet(enabled = False, timer = None)
print(hole.blockingGet()['blocking'])
result = hole.blockingSet(enabled = True, timer = None)
print(hole.blockingGet()['blocking'])
result=hole.metricsGetClientHistory(10)
print(result)