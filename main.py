import tkinter as tk
from db import init_db
from ui import App

def main():
    #init_db()
    root = tk.Tk()
    App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
