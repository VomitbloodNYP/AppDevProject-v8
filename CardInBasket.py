class CardInBasket:
    count_id = 0

    # initializer method
    def __init__(self, id, name, type, price, rarity, booster, description, inPack):
        CardInBasket.count_id += 1

        self.__id = id
        self.__name = name
        self.__type = type
        self.__price = price
        self.__rarity = rarity
        self.__booster = booster
        self.__description = description
        self.__inPack = False

    def get_id(self):
        return self.__id

    def get_name(self):
        return self.__name

    def get_type(self):
        return self.__type

    def get_price(self):
        return self.__price

    def get_rarity(self):
        return self.__rarity

    def get_booster(self):
        return self.__booster

    def get_description(self):
        return self.__description

    def get_inPack(self):
        return self.__inPack

    def set_id(self, id):
        self.__id = id

    def set_name(self, name):
        self.__name = name

    def set_type(self, type):
        self.__type = type

    def set_price(self, price):
        self.__price = price

    def set_rarity(self, rarity):
        self.__rarity = rarity

    def set_booster(self, booster):
        self.__booster = booster

    def set_description(self, description):
        self.__description = description

    def set_inPack(self, inPack):
        self.__inPack = inPack
