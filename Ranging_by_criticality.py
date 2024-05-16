from z3 import *

# Создание объекта Optimize
opt = Optimize()

# Примерные данные из таблицы
hosts = [f"Host{i}" for i in range(1, 10)] + ["Risk Host"]
uzs = [f"U{i}" for i in range(1, 7)]
actions = [
    {"id": 1, "hosts": ["Host1"], "uzs": ["U1"], "result_hosts": ["Host7"], "result_uzs": [], "time": 1},
    {"id": 2, "hosts": ["Host1"], "uzs": ["U1"], "result_hosts": ["Host4"], "result_uzs": [], "time": 1},
    {"id": 3, "hosts": ["Host1", "Host4"], "uzs": ["U3"], "result_hosts": ["Host2"], "result_uzs": [], "time": 2},
    {"id": 4, "hosts": ["Host7"], "uzs": [], "result_hosts": [], "result_uzs": ["U2", "U6"], "time": 2},
    {"id": 5, "hosts": ["Host4"], "uzs": ["U1"], "result_hosts": ["Host6"], "result_uzs": [], "time": 1},
    {"id": 6, "hosts": ["Host6"], "uzs": [], "result_hosts": [], "result_uzs": ["U6"], "time": 1},
    {"id": 7, "hosts": ["Host6"], "uzs": ["U1"], "result_hosts": ["Host8"], "result_uzs": [], "time": 1},
    {"id": 8, "hosts": ["Host8"], "uzs": ["U3"], "result_hosts": ["Risk Host"], "result_uzs": [], "time": 10},
    {"id": 9, "hosts": ["Host2"], "uzs": ["U2"], "result_hosts": ["Host3"], "result_uzs": [], "time": 1},
    {"id": 10, "hosts": ["Host3"], "uzs": ["U2"], "result_hosts": ["Host5"], "result_uzs": [], "time": 3},
    {"id": 11, "hosts": ["Host5"], "uzs": [], "result_hosts": [], "result_uzs": ["U5"], "time": 1},
    {"id": 12, "hosts": ["Host5"], "uzs": ["U5"], "result_hosts": ["Risk Host"], "result_uzs": [], "time": 1},
    {"id": 13, "hosts": ["Host3"], "uzs": ["U6"], "result_hosts": ["Risk Host"], "result_uzs": [], "time": 1},
    {"id": 14, "hosts": ["Host4"], "uzs": [], "result_hosts": [], "result_uzs": ["U2", "U4"], "time": 2}
]
entry_points = ["Host1"]
risk_host = "Risk Host"

# Определение переменных для хостов и учетных записей (УЗ)
host_vars = {host: Bool(host) for host in hosts}
uz_vars = {uz: Bool(uz) for uz in uzs}
risk_host_var = host_vars[risk_host]

# Установка начальных условий (точки входа доступны)
for ep in entry_points:
    opt.add(host_vars[ep] == True)
opt.add(uz_vars["U3"] == True)
opt.add(uz_vars["U1"] == True)

# Добавление ограничений для действий
for action in actions:
    action_var = Bool(f"action_{action['id']}")
    host_conditions = [host_vars[host] for host in action["hosts"]]
    uz_conditions = [uz_vars[uz] for uz in action["uzs"]]
    prerequisites = And(Or(*host_conditions), Or(*uz_conditions) if uz_conditions else True)
    opt.add(Implies(action_var, prerequisites))

    # Обновление доступности хостов и УЗ после выполнения действия
    for new_host in action["result_hosts"]:
        opt.add(Implies(action_var, host_vars[new_host] == True))
    for new_uz in action["result_uzs"]:
        opt.add(Implies(action_var, uz_vars[new_uz] == True))

    # Добавление времени выполнения действия
    opt.add_soft(action_var, weight=action["time"])

# Цель: сделать RiskHost доступным
opt.add(risk_host_var == True)

# Минимизация времени выполнения всех действий
objective = Sum([If(Bool(f"action_{action['id']}"), action["time"], 0) for action in actions])
opt.minimize(objective)

# Поиск решения
if opt.check() == sat:
    print("Найдено решение:")
    model = opt.model()
    for host in hosts:
        print(f'{host} = {model[host_vars[host]]}')
    for uz in uzs:
        print(f'{uz} = {model[uz_vars[uz]]}')
    print(f'Risk Host = {model[risk_host_var]}')

    # Ранжирование по критичности
    criticality = {}
    for action in actions:
        for host in action["hosts"]:
            if host not in criticality:
                criticality[host] = 0
            criticality[host] += 1 / action["time"]
        for uz in action["uzs"]:
            if uz not in criticality:
                criticality[uz] = 0
            criticality[uz] += 1 / action["time"]

    # Дополнительные факторы критичности
    for action in actions:
        for host in action["hosts"]:
            criticality[host] += len(action["result_hosts"]) / action["time"]
        for uz in action["uzs"]:
            criticality[uz] += len(action["result_uzs"]) / action["time"]

    # Учет стратегически важных хостов
    for action in actions:
        if risk_host in action["result_hosts"]:
            for host in action["hosts"]:
                criticality[host] *= 2  # Увеличиваем критичность стратегически важных хостов
            for uz in action["uzs"]:
                criticality[uz] *= 2  # Увеличиваем критичность стратегически важных УЗ
        for result_host in action["result_hosts"]:
            if model[host_vars[result_host]] == True:
                for host in action["hosts"]:
                    criticality[host] *= 2
                for uz in action["uzs"]:
                    criticality[uz] *= 2

    # sorted_criticality = sorted(criticality.items(), key=lambda item: item[1], reverse=True)
    # print("Ранжирование по критичности:")
    # for item in sorted_criticality:
    #     print(f"{item[0]}: {item[1]}")

else:
    print("Решение не найдено")

#Нормализация
host_criticality=[None]*8
for i in range (0, 8):
    host_criticality[i]=criticality[f'Host{i+1}']
sum=0
for i in range (0, 8):
    sum=sum+host_criticality[i]
for i in range (0, 8):
    host_criticality[i]=round(host_criticality[i]/sum*100, 2)
print('Критичность хостов - ', end='')
print(host_criticality )

U_criticality=[None]*6
for i in range (0, 6):
    try:
        U_criticality[i]=criticality[f'U{i+1}']
    except KeyError:
        U_criticality[i]=0
sum=0
for i in range (0, 6):
    sum=sum+U_criticality[i]
for i in range (0, 6):
    U_criticality[i]=round(U_criticality[i]/sum*100, 2)
print('Критичность учетных записей - ', end='')
print(U_criticality)