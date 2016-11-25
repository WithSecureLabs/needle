from printer import Colors


# ======================================================================================================================
# UTILS
# ======================================================================================================================
def print_question(txt):
    question = "{CS}[>][QUESTION]{CE} {txt}".format(CS=Colors.B, CE=Colors.N, txt=txt)
    return raw_input(question).strip()

# ======================================================================================================================
# SUPPORT FOR MENU AND USER CHOICES
# ======================================================================================================================
def choose_from_list(options, choose=True):
    """Show menu on screen, let user choose from list of options."""
    # Convert list to numbered dict
    dict_opts = {i: options[i] for i in range(len(options))}
    # Render menu
    for num, val in dict_opts.items():
        ll = '\t\t%s - %s' % (num, val.strip())
        print(ll)
    # Get choice
    if choose:
        choice = print_question('Please select a number: ')
        chosen_val = dict_opts[int(choice)]
        return chosen_val.strip()


def choose_from_list_data_protection(options, choose=True):
    """Similar to choose_from_list, but also show the data protection class for the file."""
    # Convert list to numbered dict
    dict_opts = {i: options[i] for i in range(len(options))}
    # Render menu
    for num, val in dict_opts.items():
        fname, dp = val[0], val[1]
        fname = fname.strip(''''"''')
        col_start, col_end = Colors.G, Colors.N
        if dp == 'NSFileProtectionNone':
            col_start = Colors.R
        if dp == 'NSFileProtectionCompleteUntilFirstUserAuthentication':
            col_start = Colors.O
        ll = '\t{num:<3} - [{CS}{dataprotection:<52}{CE}] {fname}'.format(num=num, dataprotection=dp, fname=fname,
                                                                          CS=col_start, CE=col_end)
        print(ll)
    # Get choice
    if choose:
        choice = print_question('Please select a number: ')
        chosen_val = dict_opts[int(choice)]
        fname = chosen_val[0].strip()
        fname = fname.strip(''''"''')
        return fname


def choose_boolean(message):
    question = "{} [y/N]: ".format(message)
    choice = print_question(question)
    if choice.lower() == 'y': return True
    elif choice.lower() == 'n': return False
    else: raise Exception('Please enter "y" or "n"')
