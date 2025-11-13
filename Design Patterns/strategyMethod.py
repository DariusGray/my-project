#Without Strategy Method

def calculate_total(amount, user_type):
    if user_type == "student":
        discount = amount * 0.20   # 20%
    elif user_type == "vip":
        discount = amount * 0.30   # 30%
    else:
        discount = 0

    return amount - discount


print(calculate_total(100, "student"))
print(calculate_total(100, "vip"))

#With Strategy Method
def student_discount(amount):
    return amount * 0.80   # pay 80%

def vip_discount(amount):
    return amount * 0.70   # pay 70%

def no_discount(amount):
    return amount          # pay full


def calculate_total(amount, discount_strategy):
    return discount_strategy(amount)


print(calculate_total(100, student_discount))  # 80
print(calculate_total(100, vip_discount))      # 70
print(calculate_total(100, no_discount))       # 100
