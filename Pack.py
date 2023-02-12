# Pack class
class Pack:
    count_id = 0

    # initializer method
    def __init__(self, pack_name, pack_count, pack_price):
        Pack.count_id += 1
        self.__pack_id = Pack.count_id
        self.__pack_name = pack_name
        self.__pack_count = pack_count
        self.__pack_price = pack_price

    # accessor methods
    def get_pack_id(self):
        return self.__pack_id

    def get_pack_name(self):
        return self.__pack_name

    def get_pack_price(self):
        return self.__pack_price

    def get_pack_count(self):
        return self.__pack_count

    # mutator methods
    def set_pack_id(self, pack_id):
        self.__pack_id = pack_id

    def set_pack_name(self, pack_name):
        self.__pack_name = pack_name

    def set_pack_price(self, pack_price):
        self.__pack_price = pack_price

    def set_pack_count(self, pack_count):
        self.__pack_count = pack_count

    # many methods i want to die
    def calculate_pack_price(self):
        return self.__pack_price * self.__pack_count
