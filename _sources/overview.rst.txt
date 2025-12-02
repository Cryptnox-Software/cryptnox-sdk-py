Cryptnox SDK Python Overview
==============================

``cryptnox_sdk_py`` is a Python 3 library used to communicate with the **Cryptnox Smartcard Applet**.
It provides a high-level API to manage Cryptnox Hardware Wallet Cards, including initialization,
secure channel setup, seed management, and cryptographic signing.

Supported Hardware
------------------

- **Cryptnox smart cards** 💳
- **Standard PC/SC smart card readers**: either USB NFC reader or a USB smart card reader

Get your cards and readers here: `shop.cryptnox.com <https://shop.cryptnox.com>`_

Features
--------

- Establish communication with Cryptnox smart cards
- Initialize and manage card lifecycle
- Secure channel authentication and pairing
- Seed generation and restoration (BIP32 / BIP39 compatibility)
- ECDSA secp256k1 signing for blockchain applications

Installation
------------

From PyPI
~~~~~~~~~

.. code-block:: bash

   pip install cryptnox_sdk_py

From source
~~~~~~~~~~~

.. code-block:: bash

   git clone https://github.com/cryptnox/cryptnox-sdk-py.git
   cd cryptnox-sdk-py
   pip install .

Requirements
~~~~~~~~~~~~

- Python 3.11 – 3.13.7
- PC/SC Smart Card service (``pcscd``) on Linux

On Linux, ensure the PC/SC service is running:

.. code-block:: bash

   sudo systemctl start pcscd
   sudo systemctl enable pcscd

Quick Usage Examples
--------------------

1. Connect to a Cryptnox Card
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   import cryptnox_sdk_py
   from cryptnox_sdk_py import exceptions

   connection = None
   try:
       connection = cryptnox_sdk_py.Connection(0)
       card = cryptnox_sdk_py.factory.get_card(connection)
       # Card is loaded and can be used
       print(f"Card serial number: {card.serial_number}")
   except exceptions.ReaderException:
       print("Reader not found at index")
   except exceptions.CryptnoxException as error:
       # Issue loading the card
       print(error)
   finally:
       # Always close the connection when done
       if connection:
           connection.disconnect()

2. Test PIN code
~~~~~~~~~~~~~~~~

In the PIN verification example below the card must be initialized before calling verify_pin.

.. code-block:: python

   import cryptnox_sdk_py
   from cryptnox_sdk_py import exceptions

   connection = None
   try:
       # Connect to the Cryptnox card first
       connection = cryptnox_sdk_py.Connection(0)  # Connect to card at index 0
       card = cryptnox_sdk_py.factory.get_card(connection)
       
       # Once connected, verify the PIN
       pin_to_test = "1234"  # Example PIN
       card.verify_pin(pin_to_test)
       print("PIN verified successfully. Card is ready for operations.")
   except exceptions.ReaderException:
       print("Reader not found at index")
   except exceptions.CryptnoxException as error:
       print(f"Error loading card: {error}")
   except exceptions.PinException:
       print("Invalid PIN code.")
   except exceptions.DataValidationException:
       print("Invalid PIN length or PIN authentication disabled.")
   except exceptions.SoftLock:
       print("Card is locked. Please power cycle the card.")
   finally:
       # Always close the connection when done
       if connection:
           connection.disconnect()

3. Generate a new seed
~~~~~~~~~~~~~~~~~~~~~~

In the example below the card must be initialized before generating a seed.

.. code-block:: python

   import binascii
   import cryptnox_sdk_py
   from cryptnox_sdk_py import exceptions

   PIN = "1234"  # or "" if the card was opened via challenge-response

   def main():
       connection = None
       try:
           connection = cryptnox_sdk_py.Connection(0)
           card = cryptnox_sdk_py.factory.get_card(connection)
           
           seed_uid = card.generate_seed(PIN)
           # seed_uid is of type bytes: display in hex for readability
           print("Seed (primary node m) UID:", binascii.hexlify(seed_uid).decode())
       except exceptions.ReaderException:
           print("Reader not found at index")
       except exceptions.CryptnoxException as err:
           print(f"Error loading card: {err}")
       except exceptions.KeyAlreadyGenerated:
           print("A seed is already generated on this card.")
       except exceptions.KeyGenerationException as err:
           print(f"Failed to generate seed: {err}")
       finally:
           # Always close the connection when done
           if connection:
               connection.disconnect()

   if __name__ == "__main__":
       main()

Documentation
-------------

📚 Full API reference: https://cryptnox.github.io/cryptnox-sdk-py/

License
-------

cryptnox-sdk-py is dual-licensed:

- **LGPL-3.0** for open-source projects and proprietary projects that comply with LGPL requirements
- **Commercial license** for projects that require a proprietary license without LGPL obligations (see COMMERCIAL.md for details)

For commercial inquiries, contact: contact@cryptnox.com
