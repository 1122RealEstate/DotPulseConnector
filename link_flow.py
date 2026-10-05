"""Pairing a phone through DotPulse Link, as a conversation: what was sent in, what to say back.

One flow whatever carries the message. Telegram's handler, the ``dotpulse_pair`` tool and the
``/dotpulse`` command all call ``begin`` with the text they were given and show what it returns;
none of them decides anything. Nor does this file: whether a Pairing ID is good, who may connect
and what a link may carry are the Link service's answers.

The Pairing ID is used once, here, and is not returned, stored or logged.
"""
from __future__ import annotations

import time

import link_client
import link_crypto

#: What a person is told, by outcome. One place, so the three surfaces say the same thing.
SAY = {
    "none": "Para conectar DotPulse, abre la app en tu teléfono, pulsa «Copiar conexión» y pega aquí lo que copie.",
    "damaged": "Ese Pairing ID está incompleto o dañado. En DotPulse pulsa «Copiar conexión» otra vez y pégalo entero.",
    "several": "Hay más de un Pairing ID en el mensaje. En DotPulse pulsa «Copiar conexión» y pega solo ese.",
    "not-configured": "Este Hermes todavía no tiene configurado el servicio DotPulse Link, así que no puede conectarse con DotPulse.",
    "unreachable": "No pude contactar con DotPulse. Comprueba la conexión a Internet de este Hermes y genera un Pairing ID nuevo.",
    "incompatible": "Este conector de DotPulse (versión %s) ya no es compatible con el servicio de DotPulse. Actualízalo y genera una conexión nueva. "
                    "El Pairing ID no se ha usado." % link_client.VERSION,
    "slow-down": "Demasiados intentos seguidos. Espera unos minutos y genera un Pairing ID nuevo en DotPulse.",
    "expired": "Ese Pairing ID ha caducado. En DotPulse pulsa «Copiar conexión» para generar otro.",
    "rejected": "Ese Pairing ID no es válido o ya se usó. En DotPulse pulsa «Copiar conexión» para generar otro.",
    "unverified": "No pude verificar el teléfono que generó ese Pairing ID. No se conectó nada. Genera otro en DotPulse.",
    "pending": "DotPulse quiere conectar «%(device)s» con este Hermes.\n\nCódigo de verificación: %(code)s\n\n"
               "Hacen falta dos confirmaciones, y tienes 2 minutos:\n"
               "1. En DotPulse, en tu teléfono: verás esta solicitud con el mismo código. Pulsa Autorizar.\n"
               "2. Aquí: confirma que ese teléfono es el tuyo%(how)s.\n\n"
               "Si tu propio DotPulse no está mostrando este código ahora mismo, no confirmes: "
               "alguien está intentando conectar su teléfono a tu Hermes.",
    "confirmed": "Confirmado aquí. En cuanto pulses Autorizar en DotPulse, «%(device)s» quedará conectado.",
    "hermes-rejected": "Solicitud rechazada desde Hermes. No se conectó nada.",
    "nothing-waiting": "No hay ninguna solicitud de DotPulse esperando confirmación aquí.",
    "several-waiting": "Hay varias solicitudes esperando. Indica cuál con su código de solicitud.",
    "connected": "DotPulse conectado. «%(device)s» ya puede usar este Hermes.",
    "owner-rejected": "La solicitud se rechazó en DotPulse. No se conectó nada.",
    "unanswered": "Nadie confirmó la solicitud en DotPulse a tiempo. No se conectó nada. Para intentarlo de nuevo, pulsa «Copiar conexión» otra vez.",
    "revoked": "La solicitud se canceló desde DotPulse. No se conectó nada.",
    "failed": "No pude completar la conexión con DotPulse. Genera un Pairing ID nuevo e inténtalo otra vez.",
}


def begin(text: str, origin: str) -> dict:
    """Read a message, and if it carries exactly one well-formed Pairing ID, present it.

    Returns ``{"state", "message"}`` and, when a request is now waiting on the phone, ``device``,
    ``code`` and ``claim_id``. ``origin`` is ``"telegram"`` or ``"hermes"``.
    """
    found = link_crypto.find(text)
    if not found:
        state = "damaged" if link_crypto.MENTION.search(text or "") else "none"
        return {"state": state, "message": SAY[state]}
    if len(found) > 1:
        return {"state": "several", "message": SAY["several"]}
    try:
        result = link_client.redeem(found[0], origin)
    except link_client.LinkError as e:
        state = e.code if e.code in SAY else "failed"
        return {"state": state, "message": SAY[state]}
    state = result["state"]
    if state != "pending":
        return {"state": state, "message": SAY.get(state, SAY["failed"])}
    link_client.ensure_agent()    # it waits for the owner's answer and keeps the link afterwards
    shown = {"device": result["device"], "code": link_crypto.spaced(result["code"])}
    return {"state": "pending", "message": SAY["pending"] % dict(shown, how=" escribiendo /dotpulse confirmar (o /dotpulse rechazar si no lo es)"), "claim_id": result["claim_id"], "confirm_by": result["confirm_by"], **shown}


def ended(claim_id: str) -> dict | None:
    """How a pairing that was left waiting turned out, or None while the owner has not answered."""
    done = link_client.outcome(claim_id)
    if not done:
        return None
    state = {"rejected": "owner-rejected", "expired": "unanswered"}.get(done.get("state"), done.get("state"))
    if state == "hermes-rejected":
        return {"state": state, "message": SAY[state], "link_id": ""}
    if state not in SAY:
        state = "failed"
    return {"state": state, "message": SAY[state] % {"device": done.get("device", "tu teléfono")} if "%(" in SAY[state] else SAY[state],
            "link_id": done.get("link_id", "")}


def wait(claim_id: str, seconds: float, sleep=time.sleep, clock=time.time) -> dict | None:
    deadline = clock() + seconds
    while clock() < deadline:
        done = ended(claim_id)
        if done:
            return done
        sleep(0.5)
    return ended(claim_id)


def _the_waiting(which: str = ""):
    """The claim an answer given in Hermes refers to: the only one waiting, or the one named."""
    waiting = link_client.waiting_claims() if not which else [c for c in link_client.pending_claims() if c["claim_id"].startswith(which.lower())]
    if not waiting:
        return None, "nothing-waiting"
    if len(waiting) > 1:
        return None, "several-waiting"
    return waiting[0], ""


def confirm(which: str = "") -> dict:
    """The owner says, in Hermes, that the phone asking is theirs."""
    claim, problem = _the_waiting(which)
    if claim is None:
        return {"state": problem, "message": SAY[problem]}
    link_client.confirm_claim(claim["claim_id"])
    link_client.ensure_agent()
    return {"state": "confirmed", "message": SAY["confirmed"] % {"device": claim.get("device_name", "tu teléfono")}, "claim_id": claim["claim_id"]}


def reject(which: str = "") -> dict:
    claim, problem = _the_waiting(which)
    if claim is None:
        return {"state": problem, "message": SAY[problem]}
    link_client.reject_claim(claim["claim_id"])
    return {"state": "hermes-rejected", "message": SAY["hermes-rejected"], "claim_id": claim["claim_id"]}


def connections() -> list:
    """Every phone linked to this Hermes, with what the service says of each right now."""
    out = []
    for link in link_client.links():
        try:
            out.append(link_client.link_status(link))
        except link_client.LinkError:
            out.append({"link_id": link["link_id"], "device": link.get("device_name", ""), "state": "unknown", "capabilities": []})
    return out


def describe(connections_: list) -> str:
    if not connections_:
        return ""
    words = {"connected": "conectado", "authorized": "autorizado, sin enlace todavía", "revoked": "revocado", "unknown": "sin respuesta de DotPulse"}
    lines = []
    for c in connections_:
        state = words.get(c.get("state"), str(c.get("state")))
        if c.get("state") == "connected":
            state += ", en línea" if c.get("online") else ", reconectando"
        capabilities = ", ".join(x.get("id", "") if isinstance(x, dict) else str(x) for x in c.get("capabilities", [])) or "ninguna"
        lines.append("• %s — %s — %s — capacidades: %s" % (c.get("device") or "iPhone", c["link_id"][:12], state, capabilities))
    return "Conectados con DotPulse Link:\n" + "\n".join(lines) + "\n\n/dotpulse desconectar <identificador>"


def disconnect(prefix: str) -> str:
    matches = link_client.find_links(prefix)
    if len(matches) != 1:
        return "No hay ninguna conexión con ese identificador." if not matches else "Ese identificador coincide con varias conexiones. Escribe más caracteres."
    link_client.revoke(matches[0])
    return "Conexión revocada. «%s» ya no puede usar este Hermes; para volver a conectar hará falta un Pairing ID nuevo." % matches[0].get("device_name", "iPhone")
