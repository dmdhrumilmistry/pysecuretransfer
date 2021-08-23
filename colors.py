from os import system


class TerminalColor:
    '''
    Make your program attractive by using TerminalColors.
    Foreground Colors: BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, LIGHT_GRAY and CYAN
    Background Colors: BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, LIGHT_GRAY and CYAN
    Style: NORMAL, BOLD, ITALIC, UNDERLINE
    Errors: ValueError
    '''

    def __init__(self, fgcolor:str='LIGHT_GRAY', bgcolor='BLACK', style='NORMAL') -> None:
        __author__ = 'Dhrumil Mistry'

        system('color')
        self.foreground_colors = {  'BLACK' : '30',
                                    'RED' : '31',
                                    'GREEN' : '32',
                                    'YELLOW' : '33',
                                    'BLUE' : '34',
                                    'MAGENTA' : '35',
                                    'CYAN' : '36',
                                    'LIGHT_GRAY' : '37',
                                }

        self.background_colors = {  'BLACK' : '40',
                                    'RED' : '41',
                                    'GREEN' : '42',
                                    'YELLOW' : '43',
                                    'BLUE' : '44',
                                    'MAGENTA' : '45',
                                    'CYAN' : '46',
                                    'LIGHT_GRAY' : '47',
                                }


        self.styles = { 'NORMAL' : '\033[0m',
                        'BOLD' : '\033[1m',
                        'ITALIC' : '\033[3m',        
                        'UNDERLINE' : '\033[4m',
                        }


        self.RESET = '\033[0m'

        # set default values
        self.check_values(fgcolor, bgcolor, style, set_as_default=True)

    
    def check_values(self, fgcolor:str, bgcolor:str, style:str, set_as_default:bool=False):
        '''
        if values are valid returns true else raises ValueError
        '''
        if fgcolor in self.foreground_colors:
            if set_as_default:
                self.FCOLOR = self.foreground_colors[fgcolor]
        else:
            raise ValueError(f'TerminalColor has no foreground color named {fgcolor}, Available Colors: BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, LIGHT_GRAY and CYAN')

        if bgcolor in self.background_colors:
            if set_as_default:
                self.BGCOLOR = self.background_colors[bgcolor]
        else: 
            raise ValueError(f'TerminalColor has no background color named {bgcolor}, Available Colors: BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, LIGHT_GRAY and CYAN')


        if style in self.styles:
            if set_as_default:
                self.STYLE = self.styles[style]
        else:
            raise ValueError(f'TerminalColor has no style named {style}, Available Styles: ITALIC, BOLD, UNDERLINE')

        return True


    def cprint(self, text:str, end='\n', use_default:bool=True, fgcolor:str='LIGHT_GRAY', bgcolor:str='BLACK', style:str='NORMAL'):
        '''
        print colorful text with autoreset
        fgcolors: BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, LIGHT_GRAY, CYAN
        bgcolors: BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, LIGHT_GRAY, CYAN
        style: NORMAL, BOLD, ITALIC, UNDERLINE
        '''
        # use default value if true
        if use_default:
            color = f'\033[{self.FCOLOR};{self.BGCOLOR}m'
            style = self.STYLE
        
        # else check if values are valid then use those values 
        else: 
            self.check_values(fgcolor, bgcolor, style)
            color = f'\033[{self.foreground_colors[fgcolor]};{self.background_colors[bgcolor]}m'
            style = self.styles[style]

        # print color text with autoreset
        print(f'{self.RESET}{style}{color}{text}{self.RESET}', end=end)


if __name__ == '__main__':
    # create obj with default values
    colorize = TerminalColor(fgcolor='YELLOW', style='UNDERLINE')

    # override default values
    colorize.cprint(' TerminalCOLOR ', use_default=False, fgcolor='YELLOW', bgcolor='RED', style='BOLD')

    # using default values
    colorize.cprint('Author: Dhrumil Mistry\n')

    # print help
    help(TerminalColor)