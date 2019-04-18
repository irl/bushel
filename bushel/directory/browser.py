import tkinter as tk
from tkinter.scrolledtext import ScrolledText

import bushel.directory.remote

class Application(tk.Frame):
    def __init__(self, master=None):
        super(Application, self).__init__(master)
        self.grid()  
        self.createWidgets()


    def createWidgets(self):
        self.mondialLabel = tk.Label(self, text='Network Status Consensus')
        self.mondialLabel.grid()
        self.scrolledText = ScrolledText(self)
        self.scrolledText.grid()
        self.scrolledText.insert(tk.END, bushel.directory.remote.consensus()
              .decode('utf-8'))
        self.scrolledText.config(state=tk.DISABLED)
        self.quitButton = tk.Button(self, text='Quit', command=self.quit)
        self.quitButton.grid()

if __name__ == "__main__":
    app = Application()
    app.master.title('bushel directory')
    app.mainloop()
