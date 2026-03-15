from __future__ import annotations

import json

from django import forms

from .models import BehaviorEvent, PhishingScan


class PhishingScanForm(forms.Form):
    input_type = forms.ChoiceField(
        choices=PhishingScan.InputType.choices,
        initial=PhishingScan.InputType.URL,
        widget=forms.RadioSelect,
    )
    target_url = forms.CharField(
        required=False,
        label='URL',
        max_length=2048,
        widget=forms.TextInput(attrs={'placeholder': 'https://suspicious.example or any URL', 'class': 'input'}),
    )
    raw_content = forms.CharField(
        required=False,
        label='Message or HTML Source',
        widget=forms.Textarea(attrs={'rows': 5, 'placeholder': 'Paste suspicious email, SMS, or HTML content'}),
    )
    headers = forms.CharField(
        required=False,
        label='Full Email Headers',
        widget=forms.Textarea(attrs={'rows': 4, 'placeholder': 'Paste raw email headers for deeper inspection'}),
    )

    def clean(self):
        cleaned = super().clean()
        input_type = cleaned.get('input_type')

        if input_type == PhishingScan.InputType.URL and not cleaned.get('target_url'):
            self.add_error('target_url', 'Provide a URL to analyse.')
        if input_type in {PhishingScan.InputType.MESSAGE, PhishingScan.InputType.HEADERS} and not cleaned.get('raw_content'):
            self.add_error('raw_content', 'Provide the message or HTML content.')

        headers = cleaned.get('headers')
        if headers:
            try:
                cleaned['headers'] = json.loads(headers)
            except json.JSONDecodeError:
                # Parse raw RFC 2822 email headers: "Key: Value\nKey: Value"
                parsed: dict[str, str] = {}
                current_key: str | None = None
                for line in headers.splitlines():
                    if ':' in line and not line.startswith((' ', '\t')):
                        key, _, value = line.partition(':')
                        current_key = key.strip()
                        parsed[current_key] = value.strip()
                    elif current_key and line.startswith((' ', '\t')):
                        # Continuation line (folded header)
                        parsed[current_key] += ' ' + line.strip()
                cleaned['headers'] = parsed if parsed else {'raw': headers}

        return cleaned


class DocumentAnalysisForm(forms.Form):
    file = forms.FileField(
        allow_empty_file=False,
        label='Upload Document',
        widget=forms.ClearableFileInput(attrs={'accept': '.pdf,.png,.jpg,.jpeg,.doc,.docx'}),
    )
    run_ocr = forms.BooleanField(required=False, initial=True, label='Run OCR extraction')
    run_semantic = forms.BooleanField(required=False, initial=True, label='Semantic consistency check')


class BehaviorEventForm(forms.ModelForm):
    class Meta:
        model = BehaviorEvent
        fields = [
            'actor_identifier',
            'event_type',
            'occurred_at',
            'location',
            'device',
            'metadata',
        ]
        widgets = {
            'occurred_at': forms.DateTimeInput(attrs={'type': 'datetime-local'}),
            'metadata': forms.Textarea(attrs={'rows': 3, 'placeholder': '{"ip": "...", "resource": "..."}'}),
        }

    def clean_metadata(self):
        metadata = self.cleaned_data.get('metadata')
        if isinstance(metadata, dict):
            return metadata
        if metadata:
            try:
                return json.loads(metadata)
            except json.JSONDecodeError as exc:
                raise forms.ValidationError('Metadata must be valid JSON.') from exc
        return {}


class MalwareScanForm(forms.Form):
    file = forms.FileField(
        allow_empty_file=False,
        label='Upload File',
        widget=forms.ClearableFileInput(attrs={'accept': '*/*'}),
    )
    enforce_policy = forms.BooleanField(
        required=False,
        initial=True,
        label='Apply security policies (quarantine high risk files)',
    )


class AlertStatusForm(forms.Form):
    alert_id = forms.IntegerField(widget=forms.HiddenInput)
    action = forms.ChoiceField(
        choices=[
            ('acknowledge', 'Acknowledge'),
            ('resolve', 'Resolve'),
            ('close', 'Close without action'),
        ]
    )
    note = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={'rows': 3, 'placeholder': 'Optional note for audit trail'}),
    )

    def clean_action(self):
        action = self.cleaned_data['action']
        valid_actions = {'acknowledge', 'resolve', 'close'}
        if action not in valid_actions:
            raise forms.ValidationError('Invalid action.')
        return action

