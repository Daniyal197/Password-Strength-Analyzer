import tkinter as tk
from tkinter import ttk
from analyzer import analyze_password, load_common_passwords
# Rating ke hisaab se colors (red -> green gradient feel)
RATING_COLORS = {
    "Very Weak": "#e74c3c",
    "Weak": "#e67e22",
    "Medium": "#f1c40f",
    "Strong": "#2ecc71",
    "Very Strong": "#27ae60",
}
class PasswordAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Analyzer")
        self.root.geometry("520x680")
        self.root.configure(bg="#1e1e2e")
        self.root.resizable(False, False)

        self.common_passwords = load_common_passwords("common_passwords.txt")
        self.show_password = tk.BooleanVar(value=False)

        self._build_ui()
    def _build_ui(self):
        title = tk.Label(
            self.root, text="🔐 Password Strength Analyzer",
            font=("Segoe UI", 16, "bold"), bg="#1e1e2e", fg="white"
        )
        title.pack(pady=(20, 10))
        entry_frame = tk.Frame(self.root, bg="#1e1e2e")
        entry_frame.pack(pady=5)

        self.entry = tk.Entry(
            entry_frame, font=("Segoe UI", 13), width=28,
            show="*", bg="#2d2d44", fg="white", insertbackground="white",
            relief="flat"
        )
        self.entry.pack(side="left", ipady=6, padx=(0, 8))
        self.entry.bind("<KeyRelease>", self.on_key_release)

        show_check = tk.Checkbutton(
            entry_frame, text="Show", variable=self.show_password,
            command=self.toggle_visibility, bg="#1e1e2e", fg="white",
            selectcolor="#2d2d44", activebackground="#1e1e2e",
            activeforeground="white"
        )
        show_check.pack(side="left")

        # ---- Strength bar ----
        self.progress = ttk.Progressbar(
            self.root, orient="horizontal", length=380,
            mode="determinate", maximum=100
        )
        self.progress.pack(pady=(20, 5))

        self.rating_label = tk.Label(
            self.root, text="Rating: -", font=("Segoe UI", 12, "bold"),
            bg="#1e1e2e", fg="white"
        )
        self.rating_label.pack(pady=(0, 15))

        # ---- Details box ----
        self.details = tk.Text(
            self.root, width=58, height=24, bg="#2d2d44", fg="#dcdcdc",
            font=("Consolas", 10), relief="flat", state="disabled",
            wrap="word"
        )
        self.details.pack(padx=15, pady=5)

    # --------------------------------------------------------
    def toggle_visibility(self):
        self.entry.config(show="" if self.show_password.get() else "*")

    # --------------------------------------------------------
    def on_key_release(self, event=None):
        password = self.entry.get()

        if not password:
            self.progress["value"] = 0
            self.rating_label.config(text="Rating: -", fg="white")
            self._set_details("Password type karo to analysis yahan dikhega...")
            return

        result = analyze_password(password, self.common_passwords)

        # Progress bar + rating update
        self.progress["value"] = result["score"]
        color = RATING_COLORS.get(result["rating"], "white")
        self.rating_label.config(
            text=f"Score: {result['score']}/100  |  Rating: {result['rating']}",
            fg=color
        )

        # Style the progress bar color to match rating
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TProgressbar", troughcolor="#2d2d44", background=color)
        v = result["variety"]
        lines = []
        lines.append(f"Length   : {result['password_length']} characters")
        lines.append(f"Entropy  : {result['entropy_bits']} bits\n")
        lines.append("Character types used:")
        lines.append(f"  Lowercase : {'✔' if v['lowercase'] else '✘'}")
        lines.append(f"  Uppercase : {'✔' if v['uppercase'] else '✘'}")
        lines.append(f"  Digits    : {'✔' if v['digit'] else '✘'}")
        lines.append(f"  Special   : {'✔' if v['special'] else '✘'}\n")

        if result["is_common_password"]:
            lines.append("⚠ Ye ek COMMON password hai - foran change karo!\n")

        if result["pattern_issues"]:
            lines.append("Weak patterns:")
            for issue in result["pattern_issues"]:
                lines.append(f"  - {issue}")
            lines.append("")

        lines.append("Estimated crack time:")
        for scenario, time_estimate in result["crack_time_estimates"].items():
            lines.append(f"  {scenario}:")
            lines.append(f"     -> {time_estimate}")
        lines.append("")

        lines.append("Suggestions:")
        for tip in result["suggestions"]:
            lines.append(f"  * {tip}")

        self._set_details("\n".join(lines))

    # --------------------------------------------------------
    def _set_details(self, text):
        self.details.config(state="normal")
        self.details.delete("1.0", tk.END)
        self.details.insert(tk.END, text)
        self.details.config(state="disabled")


if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordAnalyzerApp(root)
    root.mainloop()