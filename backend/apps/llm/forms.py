from django import forms


class ActiveModelForm(forms.Form):
    model = forms.ChoiceField(label="Modelo activo")

    def __init__(self, *args, installed, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["model"].choices = [(name, name) for name in installed]
        self.fields["model"].widget.attrs["class"] = "form-input"
