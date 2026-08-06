# Conformance harness for sgiath/reticulum.
#
#	elixir -pa <build>/lib/reticulum/ebin dump.exs kind rawfile
#
# See ../README for what a harness may and may not do.

defmodule Dump do
  alias Reticulum.Crypto
  alias Reticulum.Crypto.Fernet
  alias Reticulum.Destination
  alias Reticulum.Identity
  alias Reticulum.Packet

  @w 18
  @dest_types %{single: "single", group: "group", plain: "plain", link: "link"}
  @packet_types %{data: "data", announce: "announce", link_request: "linkrequest", proof: "proof"}

  def f(name, value), do: IO.puts(String.pad_trailing(name, @w) <> " " <> value)
  # An empty byte string prints as "-", as cmd/dump's field_hex does.
  # Hex cannot spell it, and a name followed by nothing cannot be told
  # from a truncated line.
  def hx(<<>>), do: "-"
  # A value the implementation did not produce is absent, not a crash.
  # from_private_key/1 leaves hash nil; see finding 7. Printing "-" and
  # going on shows how far the defect reaches, which one error line
  # replacing every remaining field does not.
  def hx(nil), do: "-"
  def hx(b), do: Base.encode16(b, case: :lower)

  def ratchet_public(nil), do: "-"

  def ratchet_public(priv),
    do: hx(:crypto.compute_key(:eddh, <<9>> <> :binary.copy(<<0>>, 31), priv, :x25519))

  def read_raw(path) do
    path
    |> File.read!()
    |> String.split("\n", trim: true)
    |> Enum.map(fn
      "-" -> nil
      line -> Base.decode16!(String.trim(line), case: :lower)
    end)
  end

  def invalid(reason, pairs) do
    f("invalid", reason)
    Enum.each(pairs, fn {k, v} -> f(k, Integer.to_string(v)) end)
  end

  # sgiath/reticulum exposes no entry point that yields the header
  # fields on their own, so they are read from its decoded packet.
  def header(p, raw) do
    f("flags", Base.encode16(binary_part(raw, 0, 1), case: :lower))
    f("header_type", Integer.to_string(length(p.addresses)))
    f("context_flag", if(p.context_flag == 1, do: "set", else: "unset"))
    f("transport_type", Atom.to_string(p.propagation))
    f("destination_type", Map.fetch!(@dest_types, p.destination))
    f("packet_type", Map.fetch!(@packet_types, p.type))
    f("hops", Integer.to_string(p.hops))

    case p.addresses do
      [t, _d] -> f("transport_id", hx(t))
      [_d] -> f("transport_id", "-")
    end

    f("destination_hash", hx(List.last(p.addresses)))

    f("context", context_name(:binary.first(p.context)))

    f("payload_length", Integer.to_string(byte_size(p.data)))
  end

  # Named from sgiath/reticulum's own context module,
  # lib/reticulum/packet/context.ex.
  def context_name(c) do
    alias Reticulum.Packet.Context

    cond do
      c == Context.none() -> "none"
      c == Context.path_response() -> "path_response"
      c == Context.channel() -> "channel"
      c == Context.keepalive() -> "keepalive"
      c == Context.linkidentify() -> "link_identify"
      c == Context.linkclose() -> "link_close"
      c == Context.linkproof() -> "link_proof"
      c == Context.lrrtt() -> "link_rtt"
      c == Context.lrproof() -> "link_request_proof"
      true -> Base.encode16(<<c>>, case: :lower)
    end
  end

  # sgiath/reticulum has no Link module. Packet.truncated_hash is its
  # own, and is the link id derivation minus the one step that belongs
  # to links: chopping the signalling bytes before hashing. It is
  # called as it stands, and where it disagrees the vector says so.
  # Everything else here is assembled from the reference layout and
  # handed to sgiath's own primitives.

  def link_id(raw) do
    {:ok, id} = Packet.truncated_hash(raw)
    id
  end

  def decode(raw) do
    try do
      {:ok, Packet.decode(raw)}
    rescue
      _ -> :error
    end
  end

  def run("identity", [pub]) do
    {:ok, id} = Identity.from_public_key(pub)
    f("public_key", hx(id.enc_pub <> id.sig_pub))
    f("x25519_public", hx(id.enc_pub))
    f("ed25519_public", hx(id.sig_pub))
    f("identity_hash", hx(id.hash))
  end

  def run("keyset", [priv]) do
    {:ok, id} = Identity.from_private_key(priv)
    f("private_key", hx(id.enc_sec <> id.sig_sec))
    f("x25519_private", hx(id.enc_sec))
    f("ed25519_private", hx(id.sig_sec))
    f("public_key", hx(id.enc_pub <> id.sig_pub))
    f("x25519_public", hx(id.enc_pub))
    f("ed25519_public", hx(id.sig_pub))
    f("identity_hash", hx(id.hash))
  end

  def run("destination", [name_bytes, identity_hash]) do
    name = to_string(name_bytes)
    [app | aspects] = String.split(name, ".")
    {:ok, nh} = Destination.name_hash(app, aspects)
    {:ok, dh} = Destination.hash(identity_hash, app, aspects)

    f("name", hx(name_bytes))
    f("app_name", hx(app))
    Enum.each(aspects, fn a -> f("aspect", hx(a)) end)
    f("name_hash", hx(nh))
    f("identity_hash", if(identity_hash, do: hx(identity_hash), else: "-"))
    f("destination_hash", hx(dh))
  end

  def run("signature", [pub, message, signature]) do
    {:ok, id} = Identity.from_public_key(pub)
    f("ed25519_public", hx(id.sig_pub))
    f("message_length", Integer.to_string(byte_size(message)))
    f("message_sha256", hx(:crypto.hash(:sha256, message)))
    f("signature", hx(signature))
    f("valid", if(Identity.validate(id, message, signature), do: "yes", else: "no"))
  end

  # The other direction of signature: the signature is produced, not
  # handed in. lib/reticulum/identity.ex:234.
  def run("sign", [priv, message]) do
    {:ok, id} = Identity.from_private_key(priv)
    f("private_key", hx(priv))
    f("ed25519_private", hx(binary_part(priv, 32, 32)))
    f("ed25519_public", hx(id.sig_pub))
    f("message_length", Integer.to_string(byte_size(message)))
    f("message_sha256", hx(:crypto.hash(:sha256, message)))
    f("signature", hx(Identity.sign(id, message)))
  end

  def run("announce", [raw]) do
    with true <- byte_size(raw) >= 2,
         {:ok, p} <- decode(raw) do
      # No hop limit check: the implementation has none at decode.
      payload = p.data
      ratchet_size = if p.context_flag == 1, do: 32, else: 0
      minimum = 64 + 10 + 10 + ratchet_size + 64

      if byte_size(payload) < minimum do
        invalid("short-payload", [{"payload_length", byte_size(payload)}, {"minimum_length", minimum}])
      else
        <<pub::binary-size(64), nh::binary-size(10), rh::binary-size(10), rest::binary>> = payload

        {ratchet, rest} =
          if ratchet_size > 0 do
            <<r::binary-size(32), tail::binary>> = rest
            {r, tail}
          else
            {<<>>, rest}
          end

        <<sig::binary-size(64), app_data::binary>> = rest

        dest = List.last(p.addresses)
        <<identity_hash::binary-size(16), _::binary>> = :crypto.hash(:sha256, pub)
        <<expected::binary-size(16), _::binary>> = :crypto.hash(:sha256, nh <> identity_hash)
        signed = dest <> pub <> nh <> rh <> ratchet <> app_data

        {:ok, announced} = Identity.from_public_key(pub)

        header(p, raw)
        f("public_key", hx(pub))
        f("name_hash", hx(nh))
        f("random_hash", hx(rh))
        f("ratchet", if(ratchet == <<>>, do: "-", else: hx(ratchet)))
        f("signature", hx(sig))
        f("app_data", if(app_data == <<>>, do: "-", else: hx(app_data)))
        f("identity_hash", hx(identity_hash))
        f("expected_hash", hx(expected))
        f("destination_match", if(dest == expected, do: "yes", else: "no"))
        f("signed_data", hx(signed))
        f("signature_valid", if(Identity.validate(announced, signed, sig), do: "yes", else: "no"))
      end
    else
      _ -> invalid("short-header", [{"length", byte_size(raw)}, {"minimum_length", 19}])
    end
  end

  def run("encrypted", [priv, ratchet_priv, raw]) do
    # Echoes of the input lines, so that expect holds every byte of raw.
    # Not a claim about this implementation: the harness was handed these.
    f("recipient_private", hx(priv))
    f("ratchet_private", if(ratchet_priv, do: hx(ratchet_priv), else: "-"))

    with true <- byte_size(raw) >= 2,
         {:ok, p} <- decode(raw) do
      payload = p.data

      if byte_size(payload) < 32 + 48 do
        invalid("short-payload", [{"payload_length", byte_size(payload)}, {"minimum_length", 80}])
      else
        <<ephemeral::binary-size(32), token::binary>> = payload
        <<iv::binary-size(16), rest::binary>> = token
        ct = binary_part(rest, 0, byte_size(rest) - 32)
        mac = binary_part(rest, byte_size(rest) - 32, 32)

        {:ok, id} = Identity.from_private_key(priv)

        agree = ratchet_priv || id.enc_sec

        # A refused agreement is a result, not a harness error. The
        # pinned backend refuses a point of small order rather than
        # returning the all-zero secret, and everything after the
        # agreement is then unreachable rather than wrong.
        shared =
          try do
            :crypto.compute_key(:eddh, ephemeral, agree, :x25519)
          rescue
            _ -> nil
          end

        header(p, raw)
        f("ephemeral_public", hx(ephemeral))
        f("iv", hx(iv))
        f("ciphertext", hx(ct))
        f("hmac", hx(mac))
        f("identity_hash", hx(id.hash))
        f("ratchet_public", ratchet_public(ratchet_priv))

        f("shared_key", hx(shared))

        # The salt of the derivation is the identity hash, which
        # from_private_key/1 leaves nil; see finding 7. The agreement
        # above succeeded, so the failure starts here and not before it.
        derived =
          if shared == nil do
            nil
          else
            try do
              Crypto.hkdf(shared, id.hash, <<>>, 64)
            rescue
              _ -> nil
            end
          end

        if derived == nil do
          Enum.each(
            ~w(signing_key encryption_key hmac_valid plaintext_length plaintext),
            &f(&1, "-")
          )
        else
          half = div(byte_size(derived), 2)
          <<signing::binary-size(half), encryption::binary>> = derived

          fernet = Fernet.new(derived)
          hmac_ok = Fernet.sig_valid?(fernet, token)

          opts = if ratchet_priv, do: [ratchets: [ratchet_priv]], else: []

          plaintext =
            case Identity.decrypt(id, payload, opts) do
              {:ok, pt} -> pt
              _ -> nil
            end

          f("signing_key", hx(signing))
          f("encryption_key", hx(encryption))
          f("hmac_valid", if(hmac_ok, do: "yes", else: "no"))

          case plaintext do
            nil ->
              f("plaintext_length", "-")
              f("plaintext", "-")

            pt ->
              f("plaintext_length", Integer.to_string(byte_size(pt)))
              f("plaintext", hx(pt))
          end
        end
      end
    else
      _ -> invalid("short-header", [{"length", byte_size(raw)}, {"minimum_length", 19}])
    end
  end

  # The fourth packet type. Packet.hash/1 is called for the packet hash.
  # lib/reticulum/packet.ex:113.
  def run("proof", [proved_raw, signer_public, raw]) do
    f("proved_packet", hx(proved_raw))
    f("signer_public", hx(signer_public))

    with true <- byte_size(raw) >= 2,
         {:ok, p} <- decode(raw) do
      payload = p.data
      {:ok, packet_hash} = Packet.hash(proved_raw)

      explicit = byte_size(payload) == 96
      signature = if explicit, do: binary_part(payload, 32, 64), else: payload
      on_link = byte_size(signer_public) == 32

      header(p, raw)
      f("form", if(explicit, do: "explicit", else: "implicit"))
      f("packet_hash", hx(packet_hash))
      f("proof_hash", if(explicit, do: hx(binary_part(payload, 0, 32)), else: "-"))

      f("hash_match",
        if(not explicit or binary_part(payload, 0, 32) == packet_hash,
          do: "yes",
          else: "no"
        ))

      # On a link the proof is addressed to the link id and verified
      # under a single Ed25519 public. sgiath/reticulum verifies no
      # proof anywhere, so the key goes to the same :crypto verifier
      # Identity.validate calls.
      if on_link do
        {:ok, proved} = decode(proved_raw)
        link_id = List.last(proved.addresses)
        f("link_id", hx(link_id))
        f("link_id_match", if(List.last(p.addresses) == link_id, do: "yes", else: "no"))
        f("signature", hx(signature))
        f("signer_ed25519", hx(signer_public))

        f("signature_valid",
          if(:crypto.verify(:eddsa, :none, packet_hash, signature, [signer_public, :ed25519]),
            do: "yes",
            else: "no"
          ))
      else
        signer_ed = binary_part(signer_public, 32, 32)
        {:ok, signer} = Identity.from_public_key(signer_public)
        f("proof_destination", hx(binary_part(packet_hash, 0, 16)))

        f("destination_match",
          if(List.last(p.addresses) == binary_part(packet_hash, 0, 16), do: "yes", else: "no"))

        f("signature", hx(signature))
        f("signer_ed25519", hx(signer_ed))

        f("signature_valid",
          if(Identity.validate(signer, packet_hash, signature), do: "yes", else: "no"))
      end
    else
      _ -> invalid("short-header", [{"length", byte_size(raw)}, {"minimum_length", 19}])
    end
  end

  def run("linkrequest", [raw]) do
    with true <- byte_size(raw) >= 2,
         {:ok, p} <- decode(raw) do
      payload = p.data

      # No length rule: sgiath has no Link module and refuses no
      # payload size, so the harness refuses none either.
      signalled = byte_size(payload) == 67
      header(p, raw)
      f("x25519_public", hx(binary_part(payload, 0, 32)))
      f("ed25519_public", hx(binary_part(payload, 32, 32)))
      f("signalling", if(signalled, do: hx(binary_part(payload, 64, 3)), else: "-"))

      # No mode and no MTU are decoded anywhere, so neither is filled
      # in from the reference.
      f("mode", "-")
      f("mtu", "-")
      f("link_id", hx(link_id(raw)))
    else
      _ -> invalid("short-header", [{"length", byte_size(raw)}, {"minimum_length", 19}])
    end
  end

  def run("linkproof", [request_raw, identity_public, raw]) do
    f("link_request", hx(request_raw))
    f("signer_public", hx(identity_public))

    with true <- byte_size(raw) >= 2,
         {:ok, p} <- decode(raw) do
      payload = p.data

      # No length rule here either, for the same reason.
      signalled = byte_size(payload) == 99
      id = link_id(request_raw)
      signature = binary_part(payload, 0, 64)
      x25519_public = binary_part(payload, 64, 32)
      signalling = if signalled, do: binary_part(payload, 96, 3), else: <<>>
      signer_ed = binary_part(identity_public, 32, 32)
      signed = id <> x25519_public <> signer_ed <> signalling

      {:ok, signer} = Identity.from_public_key(identity_public)

      header(p, raw)
      f("link_id", hx(id))
      f("link_id_match", if(List.last(p.addresses) == id, do: "yes", else: "no"))
      f("signature", hx(signature))
      f("x25519_public", hx(x25519_public))
      f("signalling", if(signalled, do: hx(signalling), else: "-"))
      f("mode", "-")
      f("mtu", "-")

      f("signer_ed25519", hx(signer_ed))
      f("signed_data", hx(signed))
      f("signature_valid",
        if(Identity.validate(signer, signed, signature), do: "yes", else: "no"))
    else
      _ -> invalid("short-header", [{"length", byte_size(raw)}, {"minimum_length", 19}])
    end
  end

  def run("linkdata", [request_raw, responder_private, raw]) do
    f("link_request", hx(request_raw))
    f("responder_private", hx(responder_private))

    with true <- byte_size(raw) >= 2,
         {:ok, p} <- decode(raw) do
      payload = p.data
      id = link_id(request_raw)
      context = :binary.first(p.context)

      header(p, raw)
      f("link_id", hx(id))
      f("link_id_match", if(List.last(p.addresses) == id, do: "yes", else: "no"))

      if context == Reticulum.Packet.Context.keepalive() do
        f("encrypted", "no")
        f("plaintext_length", Integer.to_string(byte_size(payload)))
        f("plaintext", if(payload == <<>>, do: "-", else: hx(payload)))
      else
        f("encrypted", "yes")

        <<iv::binary-size(16), rest::binary>> = payload
        ct = binary_part(rest, 0, byte_size(rest) - 32)
        mac = binary_part(rest, byte_size(rest) - 32, 32)

        {:ok, request} = decode(request_raw)
        peer = binary_part(request.data, 0, 32)

        shared = :crypto.compute_key(:eddh, peer, responder_private, :x25519)
        derived = Crypto.hkdf(shared, id, <<>>, 64)
        half = div(byte_size(derived), 2)
        <<signing::binary-size(half), encryption::binary>> = derived

        fernet = Fernet.new(derived)
        hmac_ok = Fernet.sig_valid?(fernet, payload)

        plaintext =
          case Fernet.decrypt(fernet, payload) do
            {:ok, pt} -> pt
            _ -> nil
          end

        f("iv", hx(iv))
        f("ciphertext", hx(ct))
        f("hmac", hx(mac))
        f("shared_key", hx(shared))
        f("signing_key", hx(signing))
        f("encryption_key", hx(encryption))
        f("hmac_valid", if(hmac_ok, do: "yes", else: "no"))

        case plaintext do
          nil ->
            f("plaintext_length", "-")
            f("plaintext", "-")

          pt ->
            f("plaintext_length", Integer.to_string(byte_size(pt)))
            f("plaintext", if(pt == <<>>, do: "-", else: hx(pt)))

            # sgiath/reticulum defines the channel context byte and has
            # no envelope code behind it. Printed absent, which fails
            # the vector. See ../README.
            if context == Reticulum.Packet.Context.channel() and byte_size(pt) >= 6 do
              f("msgtype", "-")
              f("sequence", "-")
              f("declared_length", "-")
              f("message", "-")
            end

            # sgiath/reticulum has no constant for either context and no
            # code that reads what these packets carry. Nothing to call.
            if context == 0x09 do
              f("request_time", "-")
              f("request_path_hash", "-")
              f("request_data", "-")
            end

            if context == 0x0A do
              f("request_id", "-")
              f("response_data", "-")
            end

            if context == Reticulum.Packet.Context.linkidentify() and byte_size(pt) == 128 do
              pub = binary_part(pt, 0, 64)
              sig = binary_part(pt, 64, 64)
              signed = id <> pub
              {:ok, who} = Identity.from_public_key(pub)
              f("identity_public", hx(pub))
              f("identity_hash", hx(who.hash))
              f("identity_signed", hx(signed))
              f("identity_valid",
                if(Identity.validate(who, signed, sig), do: "yes", else: "no"))
            end
        end
      end
    else
      _ -> invalid("short-header", [{"length", byte_size(raw)}, {"minimum_length", 19}])
    end
  end

  # 77 says the kind is not implemented here. cmd/check counts it as
  # skipped rather than failed; see ../README.
  def run(kind, _) do
    IO.puts(:stderr, "kind not implemented: " <> kind)
    System.halt(77)
  end
end

[kind, path] = System.argv()

try do
  Dump.run(kind, Dump.read_raw(path))
rescue
  e -> Dump.f("error", e |> Exception.message() |> String.split("\n") |> hd())
end
