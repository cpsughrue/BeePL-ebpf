open Lexing
open Term

let rec loop buffer =
  flush stdout;
  let _ = match Parser.prog Lexer.read buffer with
    | Some t ->
        Printf.printf "%s\n\n" (show_term t);
    | None -> () in
  loop buffer

let () =
  loop (from_channel stdin)
