import ahocorasick

def AC(sensitivelist: list, text: str):
    actree = ahocorasick.Automaton()
    for i in range(len(sensitivelist)):
        temp = sensitivelist[i]
        actree.add_word(temp, (i, temp))
    actree.make_automaton()

    result = actree.iter(text)
    for i in result:
        return True
    return False

if __name__ == '__main__':
    sensitivelist = ['hello', 'thank', 'you']
    text = 'hello, thank you, thank you very much.'
    print(AC(sensitivelist, text))