cryptnox_sdk_py package
==================

Subpackages
-----------

.. toctree::
   :maxdepth: 4

   cryptnox_sdk_py.card
   cryptnox_sdk_py.cryptos

Submodules
----------

cryptnox_sdk_py.binary\_utils module
-------------------------------

.. automodule:: cryptnox_sdk_py.binary_utils
   :members:
   :undoc-members:
   :show-inheritance:

cryptnox_sdk_py.connection module
----------------------------

.. automodule:: cryptnox_sdk_py.connection
   :members:
   :undoc-members:
   :show-inheritance:

cryptnox_sdk_py.crypto\_utils module
-------------------------------

.. automodule:: cryptnox_sdk_py.crypto_utils
   :members:
   :undoc-members:
   :show-inheritance:

cryptnox_sdk_py.enums module
-----------------------

.. automodule:: cryptnox_sdk_py.enums
   :members:
   :undoc-members:
   :show-inheritance:

cryptnox_sdk_py.exceptions module
----------------------------

.. automodule:: cryptnox_sdk_py.exceptions
   :members:
   :undoc-members:
   :show-inheritance:

cryptnox_sdk_py.factory module
-------------------------

.. automodule:: cryptnox_sdk_py.factory
   :members:
   :undoc-members:
   :show-inheritance:

cryptnox_sdk_py.reader module
------------------------

.. automodule:: cryptnox_sdk_py.reader
   :members:
   :undoc-members:
   :show-inheritance:

Module contents
---------------

.. automodule:: cryptnox_sdk_py
   :members:
   :undoc-members:
   :show-inheritance:

The ``cryptnox_sdk_py`` package is a library for communicating with Cryptnox cards. It exports:

.. py:currentmodule:: cryptnox_sdk_py

.. py:class:: Card
   :no-index:

   Main card interface class. Alias for :class:`cryptnox_sdk_py.card.base.Base`.

.. py:class:: Connection
   :no-index:

   Connection handler for card communication. See :class:`cryptnox_sdk_py.connection.Connection` for details.

.. py:module:: factory
   :no-index:

   Factory module for creating card instances. See :mod:`cryptnox_sdk_py.factory` for details.

.. py:module:: enums
   :no-index:

   Enumeration types module. See :mod:`cryptnox_sdk_py.enums` for details.

.. py:module:: exceptions
   :no-index:

   Exception classes module. See :mod:`cryptnox_sdk_py.exceptions` for details.

.. py:class:: SlotIndex
   :no-index:

   Card slot index enumeration. See :class:`cryptnox_sdk_py.enums.SlotIndex` for details.

.. py:class:: Derivation
   :no-index:

   Key derivation method enumeration. See :class:`cryptnox_sdk_py.enums.Derivation` for details.

.. py:class:: KeyType
   :no-index:

   Cryptographic key type enumeration. See :class:`cryptnox_sdk_py.enums.KeyType` for details.

.. py:class:: AuthType
   :no-index:

   Authentication type enumeration. See :class:`cryptnox_sdk_py.enums.AuthType` for details.

.. py:class:: SeedSource
   :no-index:

   Seed source enumeration. See :class:`cryptnox_sdk_py.enums.SeedSource` for details.

.. py:class:: Origin
   :no-index:

   Origin enumeration. See :class:`cryptnox_sdk_py.enums.Origin` for details.

.. py:data:: __version__
   :type: str
   :value: "1.0.2"

   Current version of the cryptnox_sdk_py library.