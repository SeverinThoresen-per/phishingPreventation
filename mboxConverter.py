import mailbox
import os

mbox_file = 'mail.mbox'
output_folder = 'eml_output'
os.makedirs(output_folder, exist_ok=True)
mbox = mailbox.mbox(mbox_file)

for i, message in enumerate(mbox):
    eml_path = os.path.join(output_folder, f'email_{i+1}.eml')
    with open(eml_path, 'wb') as eml_file:
        eml_file.write(bytes(message))
        
print(f"Saved {len(mbox)} emails to {output_folder}")