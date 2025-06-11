# provmap

A simple tool for processing and mapping provenance data.

## Requirements

- [TShark](https://www.wireshark.org/docs/man-pages/tshark.html)
- [SWI-Prolog (SWIPL)](https://www.swi-prolog.org/)

## Installation

1. **Install TShark**  
    Download and install TShark from the [Wireshark website](https://www.wireshark.org/download.html).
    Alternatively, a previous installation of Wireshark would include TShark.

2. **Install SWIPL**  
    Download and install SWI-Prolog from the [official site](https://www.swi-prolog.org/Download.html).

3. **Clone this repository**
     ```sh
     git clone https://github.com/yourusername/provmap.git
     cd provmap
     ```

4. **Set up a virtual environment and install dependencies**
     ```sh
     python -m venv venv
     source venv/bin/activate  # On Windows use: venv\Scripts\activate
     pip install -r requirements.txt
     ```

5. **Run the program**
     ```sh
     python -m provmap
     ```

