import re
import os
import sys
import time
import uuid
import hashlib
import sqlite3
import logging
import argparse
import warnings
import threading
import traceback
from PyPDF2 import PdfReader
from collections import deque
from queue import Queue, Empty
from watchdog.observers import Observer
from logging.handlers import RotatingFileHandler
from watchdog.events import FileSystemEventHandler

MAX_EVENTS_PER_CYCLE = 100
QUEUE_TIMEOUT = 0.1
BLOCK_SIZE = 3 * 1024 * 1024
DELAY_TIME = 1.5
MAX_QUEUE_SIZE = 1000
EVENT_CORRELATION_TIME = 4.0  # Incrementado para mejorar la correlación
EVENT_BUFFER_TIME = 5.0       # Incrementado para acumular más eventos
MAX_RETRY_ATTEMPTS = 3
RETRY_DELAY = 0.1

class GOD_MON_Handler(FileSystemEventHandler):
    def __init__(self, path_to_monitor, event_queue, debug=False):
        self.path_to_monitor = path_to_monitor
        self.event_queue = event_queue
        self.setup_logging(debug)

    def setup_logging(self, debug):
        self.logger = logging.getLogger('GOD_MON_HANDLER')
        self.logger.setLevel(logging.DEBUG if debug else logging.INFO)
        handler = RotatingFileHandler('godmon_events.log', maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s',
                                      datefmt='%Y-%m-%d %H:%M:%S')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.propagate = False

    def on_any_event(self, event):
        if not event.is_directory:
            try:
                self.event_queue.put((event.event_type, event.src_path, getattr(event, 'dest_path', None)))
                self.logger.debug(f'Evento encolado: {event.event_type} - {event.src_path}')
            except Exception as e:
                self.logger.error(f"Error al encolar evento: {e}")

class GOD_MON_Processor:
    def __init__(self, path_to_monitor, full_scan=False, debug=False):
        self.path_to_monitor = path_to_monitor
        self.full_scan = full_scan
        self.setup_logging(debug)
        self.setup_database()
        self.db_lock = threading.RLock()
        self.pause_event = threading.Event()
        self.event_buffer = []
        self.last_buffer_process_time = time.time()
        self.pending_delete_events = {}
        self.pending_create_events = {}
        self.correlated_paths = {}  # Para rastrear eventos correlacionados y evitar duplicados

    def setup_logging(self, debug):
        self.logger = logging.getLogger('GOD_MON_PROCESSOR')
        self.logger.setLevel(logging.DEBUG if debug else logging.INFO)
        handler = RotatingFileHandler('godmon_processor.log', maxBytes=10*1024*1024, backupCount=5,
                                      encoding='utf-8')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s',
                                      datefmt='%Y-%m-%d %H:%M:%S')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.propagate = False

    def clear_analyzed_files(self):
        with self.db_lock:
            try:
                self.cursor.execute("DELETE FROM analyzed_files")
                self.conn.commit()
                self.logger.info("Se han eliminado todos los registros de la tabla analyzed_files.")
            except sqlite3.Error as e:
                self.logger.error(f"Error al eliminar registros de analyzed_files: {e}")

    def setup_database(self):
        try:
            self.conn = sqlite3.connect('godmon.db', check_same_thread=False)
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.cursor = self.conn.cursor()
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS files
                (id INTEGER PRIMARY KEY,
                path TEXT UNIQUE,
                filename TEXT,
                abagnaleJR_hash TEXT,
                newton_hash TEXT,
                mendel_hash TEXT,
                file_identifier TEXT UNIQUE)
            ''')
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS metadata
                (key TEXT PRIMARY KEY, value TEXT)
            ''')
            # Agregar la nueva tabla analyzed_files
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS analyzed_files
                (file_id INTEGER PRIMARY KEY,
                analyzed BOOLEAN,
                refs TEXT,
                FOREIGN KEY(file_id) REFERENCES files(id))
            ''')
            self.conn.commit()
        except sqlite3.Error as e:
            self.logger.error(f"Error al configurar la base de datos: {e}")
            raise

    def generate_file_identifier(self):
        # Genera un identificador único para cada archivo nuevo
        return str(uuid.uuid4())

    def get_abagnaleJR_hash(self, filename):
        hasher = hashlib.md5()
        hasher.update(filename.encode('utf-8'))
        return hasher.hexdigest()

    def get_newton_hash(self, rel_path):
        hasher = hashlib.md5()
        hasher.update(rel_path.encode('utf-8'))
        return hasher.hexdigest()

    def get_mendel_hash(self, filepath):
        hasher = hashlib.md5()
        try:
            with open(filepath, 'rb') as file:
                while True:
                    chunk = file.read(BLOCK_SIZE)
                    if not chunk:
                        break
                    hasher.update(chunk)
            return hasher.hexdigest()
        except FileNotFoundError:
            self.logger.warning(f"Archivo no encontrado al calcular hash: {filepath}")
            return None
        except PermissionError:
            self.logger.warning(f"Permiso denegado al acceder al archivo: {filepath}")
            return None
        except Exception as e:
            self.logger.error(f"Error inesperado al calcular hash para {filepath}: {e}")
            return None

    def get_relative_path(self, path):
        try:
            rel_path = os.path.relpath(path, self.path_to_monitor)
            if rel_path.startswith('..'):
                raise ValueError(f"La ruta {path} está fuera del directorio monitoreado")
            return rel_path.replace('\\', '/')
        except ValueError as e:
            self.logger.error(str(e))
            return None

    def process_initial_files(self):
        try:
            last_update = self.get_last_update_time()
            current_time = time.time()
            file_count = 0
            processed_count = 0

            for root, _, files in os.walk(self.path_to_monitor):
                for file in files:
                    if self.pause_event.is_set():
                        self.logger.info("Escaneo inicial pausado")
                        self.pause_event.wait()
                        self.logger.info("Escaneo inicial reanudado")

                    file_count += 1
                    full_path = os.path.join(root, file)
                    rel_path = self.get_relative_path(full_path)

                    if rel_path:
                        try:
                            file_mtime = os.path.getmtime(full_path)
                            if self.full_scan or file_mtime > last_update:
                                self.process_file(full_path, file_mtime)
                                processed_count += 1
                                if processed_count % 100 == 0:
                                    self.logger.info(f"Procesados {processed_count} archivos de {file_count}...")
                        except OSError as e:
                            self.logger.error(f"Error al acceder al archivo {full_path}: {e}")
                            continue

            self.set_last_update_time(current_time)
            self.logger.info(f"Procesamiento inicial completado. Archivos procesados: {processed_count} de {file_count}")

        except Exception as e:
            self.logger.error(f"Error en el procesamiento inicial de archivos: {e}")
            self.logger.debug(traceback.format_exc())
            raise

    def process_file(self, filepath, file_mtime=None):
        with self.db_lock:
            try:
                rel_path = self.get_relative_path(filepath)
                if rel_path is None:
                    return

                filename = os.path.basename(rel_path)

                abagnaleJR_hash = self.get_abagnaleJR_hash(filename)
                newton_hash = self.get_newton_hash(rel_path)
                mendel_hash = self.get_mendel_hash(filepath)
                if mendel_hash is None:
                    return

                # Verificar si el archivo ya existe en la base de datos
                self.cursor.execute("SELECT file_identifier FROM files WHERE path = ?", (rel_path,))
                existing_file = self.cursor.fetchone()

                if existing_file:
                    # Actualizar archivo existente sin cambiar el file_identifier
                    self.cursor.execute("""
                        UPDATE files
                        SET filename = ?, abagnaleJR_hash = ?, newton_hash = ?, mendel_hash = ?
                        WHERE path = ?
                    """, (filename, abagnaleJR_hash, newton_hash, mendel_hash, rel_path))
                    self.logger.info(f"ACTUALIZADO: {rel_path}")
                else:
                    # Insertar nuevo archivo con un file_identifier único
                    file_identifier = self.generate_file_identifier()
                    self.cursor.execute("""
                        INSERT INTO files (path, filename, abagnaleJR_hash, newton_hash, mendel_hash, file_identifier)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (rel_path, filename, abagnaleJR_hash, newton_hash, mendel_hash, file_identifier))
                    self.logger.info(f"CREADO: {rel_path}")

                self.conn.commit()

            except sqlite3.IntegrityError as e:
                self.logger.error(f"Error de integridad de la base de datos al procesar {filepath}: {e}")
            except Exception as e:
                self.logger.error(f"Error inesperado al procesar {filepath}: {e}")
                self.logger.debug(traceback.format_exc())

    def process_events(self, event_queue, stop_event):
        while not stop_event.is_set():
            try:
                event = event_queue.get(timeout=QUEUE_TIMEOUT)
                self.event_buffer.append((time.time(), event))

                current_time = time.time()
                if current_time - self.last_buffer_process_time > EVENT_BUFFER_TIME:
                    self.process_event_buffer()
                    self.last_buffer_process_time = current_time

            except Empty:
                if self.event_buffer:
                    self.process_event_buffer()
            except Exception as e:
                self.logger.error(f"Error al procesar eventos: {e}")
                self.logger.debug(traceback.format_exc())

    def process_event_buffer(self):
        events_to_process = self.event_buffer
        self.event_buffer = []

        # Limpiar rutas correlacionadas antiguas
        self.clean_correlated_paths()

        # Ordenar eventos por tiempo
        events_to_process.sort(key=lambda x: x[0])

        # Intentar correlacionar eventos
        correlated_events = self.correlate_events(events_to_process)

        # Procesar eventos correlacionados
        for event in correlated_events:
            self.handle_event(event)

    def clean_correlated_paths(self):
        current_time = time.time()
        # Eliminar entradas más antiguas que EVENT_CORRELATION_TIME
        self.correlated_paths = {path: timestamp for path, timestamp in self.correlated_paths.items()
                                 if current_time - timestamp <= EVENT_CORRELATION_TIME}

    def correlate_events(self, events):
        correlated = []
        current_time = time.time()
        events_to_skip = set()
        
        # Limpiar eventos pendientes antiguos
        self.pending_delete_events = {k: v for k, v in self.pending_delete_events.items()
                                    if current_time - v[0] <= EVENT_CORRELATION_TIME}
        self.pending_create_events = {k: v for k, v in self.pending_create_events.items()
                                    if current_time - v[0] <= EVENT_CORRELATION_TIME}
        
        # Procesar eventos y preparar para correlación
        for idx, (timestamp, (event_type, src_path, dest_path)) in enumerate(events):
            rel_src_path = self.get_relative_path(src_path)
            rel_dest_path = self.get_relative_path(dest_path) if dest_path else None
            
            if event_type == 'moved':
                if os.path.dirname(rel_src_path) == os.path.dirname(rel_dest_path):
                    operation_type = 'renamed'
                else:
                    operation_type = 'moved'
                correlated.append((operation_type, src_path, dest_path))
                self.logger.debug(f'Evento {operation_type} directo: {rel_src_path} a {rel_dest_path}')
                events_to_skip.add(idx)
            elif event_type == 'deleted':
                if rel_src_path:
                    with self.db_lock:
                        self.cursor.execute("SELECT mendel_hash FROM files WHERE path = ?", (rel_src_path,))
                        result = self.cursor.fetchone()
                    if result:
                        mendel_hash = result[0]
                        self.pending_delete_events[mendel_hash] = (timestamp, src_path)
                        self.logger.debug(f'Evento eliminado pendiente: {rel_src_path} con hash {mendel_hash}')
                        events_to_skip.add(idx)
                    else:
                        # Archivo no encontrado en la base de datos
                        correlated.append(('deleted', src_path, None))
                        self.logger.debug(f'Evento eliminado no correlacionado: {rel_src_path}')
            elif event_type == 'created':
                mendel_hash = self.get_mendel_hash(src_path)
                if mendel_hash:
                    self.pending_create_events[mendel_hash] = (timestamp, src_path)
                    self.logger.debug(f'Evento creado pendiente: {rel_src_path} con hash {mendel_hash}')
                    events_to_skip.add(idx)
                else:
                    correlated.append(('created', src_path, None))
                    self.logger.debug(f'Evento creado no correlacionado: {rel_src_path}')
            else:
                correlated.append((event_type, src_path, dest_path))
                self.logger.debug(f'Evento directo: {event_type} - {rel_src_path}')
        
        # Intentar correlacionar eventos pendientes
        for mendel_hash in list(self.pending_create_events.keys()):
            if mendel_hash in self.pending_delete_events:
                delete_timestamp, delete_path = self.pending_delete_events[mendel_hash]
                create_timestamp, create_path = self.pending_create_events[mendel_hash]
                
                if abs(create_timestamp - delete_timestamp) <= EVENT_CORRELATION_TIME:
                    rel_delete_path = self.get_relative_path(delete_path)
                    rel_create_path = self.get_relative_path(create_path)
                    if os.path.dirname(rel_delete_path) == os.path.dirname(rel_create_path):
                        operation_type = 'renamed'
                    else:
                        operation_type = 'moved'
                    correlated.append((operation_type, delete_path, create_path))
                    self.logger.debug(f'Correlacionado como {operation_type}: {rel_delete_path} a {rel_create_path}')
                    # Eliminar de eventos pendientes
                    del self.pending_delete_events[mendel_hash]
                    del self.pending_create_events[mendel_hash]
                    # Marcar eventos para saltar
                    for idx, (ts, (et, sp, dp)) in enumerate(events):
                        if ((et == 'deleted' and sp == delete_path) or
                            (et == 'created' and sp == create_path)):
                            events_to_skip.add(idx)
        
        # Procesar eventos restantes que no han sido correlacionados
        for idx, (timestamp, (event_type, src_path, dest_path)) in enumerate(events):
            if idx in events_to_skip:
                continue
            correlated.append((event_type, src_path, dest_path))
            rel_src_path = self.get_relative_path(src_path)
            self.logger.debug(f'Evento no correlacionado: {event_type} - {rel_src_path}')
        
        return correlated

    def handle_event(self, event):
        event_type, src_path, dest_path = event
        rel_src_path = self.get_relative_path(src_path)
        rel_dest_path = self.get_relative_path(dest_path) if dest_path else None

        # Omitir eventos 'created' y 'modified' si ya han sido manejados
        if event_type in ['created', 'modified']:
            if rel_src_path in self.correlated_paths:
                self.logger.debug(f'Omitiendo evento ya manejado: {event_type} - {rel_src_path}')
                return

        # Siempre procesar eventos 'renamed' y 'moved'
        if event_type in ['moved', 'renamed']:
            self.handle_move_or_rename(src_path, dest_path, event_type)
        elif event_type == 'created':
            self.handle_create(src_path)
        elif event_type == 'modified':
            self.handle_modify(src_path)
        elif event_type == 'deleted':
            self.handle_delete(src_path)

    def handle_move_or_rename(self, src_path, dest_path, operation_type):
        with self.db_lock:
            try:
                rel_src_path = self.get_relative_path(src_path)
                rel_dest_path = self.get_relative_path(dest_path)
                if rel_src_path is None or rel_dest_path is None:
                    return

                # Obtener información del archivo existente (en la ruta de origen)
                self.cursor.execute("SELECT * FROM files WHERE path = ?", (rel_src_path,))
                existing_file = self.cursor.fetchone()

                # Verificar si ya existe un archivo en la ruta de destino
                self.cursor.execute("SELECT * FROM files WHERE path = ?", (rel_dest_path,))
                dest_file = self.cursor.fetchone()

                if dest_file:
                    # Si el archivo de destino existe, podemos eliminarlo o fusionarlo
                    # Para simplificar, eliminaremos el registro existente
                    self.cursor.execute("DELETE FROM files WHERE path = ?", (rel_dest_path,))
                    self.logger.debug(f"Eliminado registro existente en destino: {rel_dest_path}")

                if not existing_file:
                    # Si no se encuentra el archivo de origen, procesar dest_path como nuevo archivo
                    self.process_file(dest_path)
                    return

                # Obtener el file_identifier existente
                file_identifier = existing_file[6]  # Índice de file_identifier en la tupla

                mendel_hash = self.get_mendel_hash(dest_path)
                if mendel_hash is None:
                    return
                abagnaleJR_hash = self.get_abagnaleJR_hash(os.path.basename(rel_dest_path))
                newton_hash = self.get_newton_hash(rel_dest_path)

                # Actualizar la ruta y otros campos sin cambiar el file_identifier
                self.cursor.execute("""
                    UPDATE files
                    SET path = ?, filename = ?, abagnaleJR_hash = ?, newton_hash = ?, mendel_hash = ?
                    WHERE file_identifier = ?
                """, (rel_dest_path, os.path.basename(rel_dest_path), abagnaleJR_hash, newton_hash, mendel_hash, file_identifier))

                if operation_type == 'moved':
                    self.logger.info(f"MOVIDO: {rel_src_path} a {rel_dest_path}")
                elif operation_type == 'renamed':
                    self.logger.info(f"RENOMBRADO: {rel_src_path} a {rel_dest_path}")

                self.conn.commit()

                # Añadir rutas a correlated_paths para evitar procesarlas de nuevo
                current_time = time.time()
                self.correlated_paths[rel_src_path] = current_time
                self.correlated_paths[rel_dest_path] = current_time

            except sqlite3.IntegrityError as e:
                self.logger.error(f"Error de base de datos al procesar {operation_type} de {rel_src_path} a {rel_dest_path}: {e}")
            except Exception as e:
                self.logger.error(f"Error inesperado al procesar {operation_type} de {rel_src_path} a {rel_dest_path}: {e}")
                self.logger.debug(traceback.format_exc())

    def handle_create(self, path):
        if not path:
            self.logger.error("Ruta no especificada en handle_create")
            return
        rel_path = self.get_relative_path(path)
        if rel_path in self.correlated_paths:
            self.logger.debug(f'Omitiendo creación ya manejada: {rel_path}')
            return
        for attempt in range(MAX_RETRY_ATTEMPTS):
            try:
                self.process_file(path)
                # Añadir ruta a correlated_paths
                current_time = time.time()
                self.correlated_paths[rel_path] = current_time
                break
            except FileNotFoundError:
                if attempt < MAX_RETRY_ATTEMPTS - 1:
                    time.sleep(RETRY_DELAY)
                else:
                    self.logger.error(f"No se pudo procesar el archivo creado después de {MAX_RETRY_ATTEMPTS} intentos: {path}")

    def handle_modify(self, path):
        if not path:
            self.logger.error("Ruta no especificada en handle_modify")
            return
        rel_path = self.get_relative_path(path)
        if rel_path in self.correlated_paths:
            self.logger.debug(f'Omitiendo modificación ya manejada: {rel_path}')
            return
        self.process_file(path)
        # Añadir ruta a correlated_paths
        current_time = time.time()
        self.correlated_paths[rel_path] = current_time

    def handle_delete(self, path):
        with self.db_lock:
            try:
                rel_path = self.get_relative_path(path)
                if rel_path is None:
                    return
                self.cursor.execute("DELETE FROM files WHERE path = ?", (rel_path,))
                if self.cursor.rowcount > 0:
                    self.logger.info(f"ELIMINADO: {rel_path}")
                self.conn.commit()
            except sqlite3.Error as e:
                self.logger.error(f"Error de base de datos al eliminar {rel_path}: {e}")
            except Exception as e:
                self.logger.error(f"Error inesperado al eliminar {rel_path}: {e}")
                self.logger.debug(traceback.format_exc())

    def parse_files(self, limit):

        processed_count = 0

        # Mostrar en la terminal cuando se comienza a construir el diccionario de filenames
        print("Iniciando la construcción del diccionario de filenames...")

        # Obtener todos los filenames de la base de datos para facilitar la búsqueda de referencias
        with self.db_lock:
            try:
                self.cursor.execute("SELECT filename FROM files")
                filenames = [row[0] for row in self.cursor.fetchall()]
                filename_set = set(filenames)  # Convertir a conjunto para búsqueda rápida
            except sqlite3.Error as e:
                self.logger.error(f"Error al obtener filenames de la base de datos: {e}")
                return 0

        # Mostrar en la terminal cuando se ha terminado de construir el diccionario de filenames
        print("Construcción del diccionario de filenames completada.")

        with self.db_lock:
            try:
                # Seleccionar hasta 'limit' archivos que no han sido analizados
                self.cursor.execute("""
                    SELECT files.id, files.path, files.filename FROM files
                    LEFT JOIN analyzed_files ON files.id = analyzed_files.file_id
                    WHERE analyzed_files.analyzed IS NULL OR analyzed_files.analyzed = 0
                    ORDER BY files.id
                    LIMIT ?
                """, (limit,))
                files_to_process = self.cursor.fetchall()
            except sqlite3.Error as e:
                self.logger.error(f"Error al obtener archivos para procesar: {e}")
                return 0

        for file_record in files_to_process:
            file_id, rel_path, filename = file_record
            abs_path = os.path.join(self.path_to_monitor, rel_path)
            file_extension = os.path.splitext(filename)[1].lower()

            if not os.path.isfile(abs_path):
                self.logger.warning(f"El archivo ya no existe: {rel_path}. Eliminando de la base de datos.")
                with self.db_lock:
                    try:
                        self.cursor.execute("DELETE FROM files WHERE path = ?", (rel_path,))
                        self.conn.commit()
                    except sqlite3.Error as e:
                        self.logger.error(f"Error al eliminar {rel_path} de la base de datos: {e}")
                continue

            if file_extension != '.pdf':
                self.logger.debug(f"Ignorando archivo no PDF: {rel_path}")
                processed_count += 1
                continue  # Solo procesamos PDFs

            # Especificar qué archivo se está analizando
            print(f"Analizando archivo: {filename}")

            try:
                # Suprimir advertencias de PyPDF2
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    # Abrir el PDF y extraer el texto
                    with open(abs_path, 'rb') as file:
                        reader = PdfReader(file)
                        text = ""
                        for page_num in range(len(reader.pages)):
                            page = reader.pages[page_num]
                            text += page.extract_text() or ""
            except Exception as e:
                self.logger.error(f"Error al leer el archivo PDF {rel_path}: {e}")
                continue  # Pasar al siguiente archivo

            # Buscar palabras clave "NP xyz" o "OS xyz", donde xyz son 3 o 4 dígitos
            full_keyword_pattern = r'\b(?:NP\s*\d{3,4}|OS\s*\d{3,4})\b'
            references = re.findall(full_keyword_pattern, text, re.IGNORECASE)
            # Extraer las referencias completas (e.g., "NP 1234")
            full_references = re.findall(full_keyword_pattern, text, re.IGNORECASE)
            full_references = set(full_references)  # Eliminar duplicados

            # Buscar referencias a otros filenames
            filename_references = []
            for fname in filename_set:
                if fname != filename and fname.lower() in text.lower():
                    filename_references.append(fname)

            # Combinar todas las referencias encontradas
            all_references = list(full_references) + filename_references

            # Generar logs de las referencias encontradas
            if all_references:
                message = f"Para el archivo {filename} se encontró referencias: {', '.join(all_references)}."
                self.logger.info(message)


            # Marcar el archivo como analizado y guardar las referencias en la base de datos
            references_str = ', '.join(all_references)
            with self.db_lock:
                try:
                    self.cursor.execute("""
                        INSERT OR REPLACE INTO analyzed_files (file_id, analyzed, refs)
                        VALUES (?, ?, ?)
                    """, (file_id, True, references_str))
                    self.conn.commit()
                except sqlite3.Error as e:
                    self.logger.error(f"Error al actualizar el estado de análisis para {filename}: {e}")

            processed_count += 1

        return processed_count



    def get_last_update_time(self):
        with self.db_lock:
            self.cursor.execute("SELECT value FROM metadata WHERE key = 'last_update'")
            result = self.cursor.fetchone()
            return float(result[0]) if result else 0

    def set_last_update_time(self, timestamp):
        with self.db_lock:
            self.cursor.execute("INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                                ('last_update', str(timestamp)))
            self.conn.commit()

    def close(self):
        try:
            if self.conn:
                self.conn.close()
        except sqlite3.Error as e:
            self.logger.error(f"Error al cerrar la conexión de la base de datos: {e}")

def main():
    # Definir los estados
    INITIALIZING = 'INITIALIZING'
    MONITORING = 'MONITORING'
    ASSOCIATING_FILES = 'ASSOCIATING FILES'
    current_state = INITIALIZING

    parser = argparse.ArgumentParser(description='Vigila los cambios en archivos y sus conexiones, como un buen detective.')
    parser.add_argument('path', help='La ruta del directorio a espiar')
    parser.add_argument('--debug', action='store_true', help='Activa el modo debug, para ver hasta la última pavada')
    parser.add_argument('--full-scan', action='store_true', help='Fuerza un escaneo completo de todos los archivos')
    parser.add_argument('--REANALYZE', action='store_true', help='Borra los datos de análisis previos para reanalizar todos los archivos')

    args = parser.parse_args()

    ruta_a_vigilar = os.path.abspath(args.path)
    if not os.path.isdir(ruta_a_vigilar):
        print(f"Error: {ruta_a_vigilar} no es un directorio válido, ¿te fumaste algo?")
        return

    event_queue = Queue()
    stop_event = threading.Event()
    observer = None
    processor = None
    processing_thread = None
    handler = None

    # Definir el tiempo de monitoring hang
    monitoring_hang_time=10

    # Definir el límite de archivos a procesar
    files_to_process = 250

    try:
        handler = GOD_MON_Handler(ruta_a_vigilar, event_queue, debug=args.debug)
        processor = GOD_MON_Processor(ruta_a_vigilar, full_scan=args.full_scan, debug=args.debug)
        if args.REANALYZE:
            print("Eliminando datos previos de análisis (tabla analyzed_files)...")
            processor.clear_analyzed_files()
            print("Datos previos eliminados. Se reanalizarán todos los archivos.")

        print(f"Estamos vigilando el directorio: {ruta_a_vigilar}")

        # Variables para el control de estados
        current_state = INITIALIZING
        last_event_time = time.time()
        associating_files_counter = 0

        while True:
            if current_state == INITIALIZING:
                print("Iniciando escaneo inicial...")
                processor.process_initial_files()
                print("Escaneo inicial completado.")
                # Transición al estado MONITORING
                current_state = MONITORING

                # Configurar el observador y el hilo de procesamiento
                observer = Observer()
                observer.schedule(handler, path=ruta_a_vigilar, recursive=True)
                observer.start()

                stop_event.clear()
                processing_thread = threading.Thread(target=processor.process_events, args=(event_queue, stop_event))
                processing_thread.start()

                print("Iniciando monitoreo continuo.")
                print("Apretá Ctrl+C para cortar el mambo")

                last_event_time = time.time()

            elif current_state == MONITORING:
                # Verificar inactividad
                time_since_last_event = time.time() - processor.last_buffer_process_time
                timer = time.time() - last_event_time 
                if (time_since_last_event >= monitoring_hang_time and timer >= monitoring_hang_time):
                    # Transición al estado ASSOCIATING_FILES
                    print("No hay actividad reciente. Transicionando al estado 'ASSOCIATING FILES'")
                    # Detener el monitoreo
                    if observer:
                        observer.stop()
                        observer.join()
                        observer = None
                    if processing_thread:
                        stop_event.set()
                        processing_thread.join()
                        processing_thread = None
                        stop_event.clear()
                    current_state = ASSOCIATING_FILES
                    associating_files_counter = 0
                else:
                    # Esperar un poco antes de verificar nuevamente
                    time.sleep(1)

            elif current_state == ASSOCIATING_FILES:
                # Procesar archivos
                print("Procesando archivos en el estado 'ASSOCIATING FILES'...")
                # Llamar a parse_files() con el límite especificado en main
                files_processed = processor.parse_files(limit=files_to_process)
                associating_files_counter += files_processed
                print(f"Procesados {files_processed} archivos en 'ASSOCIATING FILES'.")

                # Transición de regreso al estado MONITORING
                print("Volviendo al estado 'MONITORING'")
                # Reiniciar el monitoreo
                observer = Observer()
                observer.schedule(handler, path=ruta_a_vigilar, recursive=True)
                observer.start()

                stop_event.clear()
                processing_thread = threading.Thread(target=processor.process_events, args=(event_queue, stop_event))
                processing_thread.start()

                current_state = MONITORING
                last_event_time = time.time()
            else:
                print(f"Estado desconocido: {current_state}")
                break

    except KeyboardInterrupt:
        print("\n¡Ey! Cortaste la ejecución. Nos vemos, che.")
    except Exception as e:
        print(f"Error inesperado: {e}")
        print(traceback.format_exc())
    finally:
        stop_event.set()
        if observer:
            observer.stop()
            observer.join()
        if processing_thread:
            processing_thread.join()
        if processor:
            processor.close()

if __name__ == "__main__":
    main()